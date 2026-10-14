import {
  type KeyValue,
  type Message,
  type MoqObject,
  type SubgroupHeader,
  ObjectStatus,
  parseMessage,
  protocolViolation,
  Reader,
  readKeyValues,
  subgroupHeaderFlags,
  varintSize,
} from "./wire.ts";

/** Upper bounds on peer-chosen lengths, as in the Go implementation. */
export const MaxObjectPayload = 16 << 20;
export const MaxObjectProperties = 256 << 10;

/** Buffered reader over a WebTransport (or any) byte stream. */
export class StreamReader {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private buf = new Uint8Array(0);
  private off = 0;
  private eof = false;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader();
  }

  private get buffered(): number {
    return this.buf.length - this.off;
  }

  /** Ensures n bytes are buffered; false if the stream ends first. */
  private async fill(n: number): Promise<boolean> {
    while (this.buffered < n) {
      if (this.eof) return false;
      const { value, done } = await this.reader.read();
      if (done) {
        this.eof = true;
        return this.buffered >= n;
      }
      if (this.off > 0 || this.buf.length === 0) {
        const rest = this.buf.subarray(this.off);
        const next = new Uint8Array(rest.length + value.length);
        next.set(rest);
        next.set(value, rest.length);
        this.buf = next;
        this.off = 0;
      } else {
        const next = new Uint8Array(this.buf.length + value.length);
        next.set(this.buf);
        next.set(value, this.buf.length);
        this.buf = next;
      }
    }
    return true;
  }

  /** True when the stream ended cleanly with nothing left to read. */
  async done(): Promise<boolean> {
    return !(await this.fill(1));
  }

  /** Reads n bytes; throws if the stream ends first. */
  async exact(n: number): Promise<Uint8Array> {
    if (!(await this.fill(n))) throw new EndOfStream();
    const b = this.buf.slice(this.off, this.off + n);
    this.off += n;
    return b;
  }

  async u8(): Promise<number> {
    return (await this.exact(1))[0];
  }

  async varint(): Promise<number> {
    if (!(await this.fill(1))) throw new EndOfStream();
    const n = varintSize(this.buf[this.off]);
    return new Reader(await this.exact(n)).varint();
  }

  /** Reads one control message. */
  async message(): Promise<Message> {
    const type = await this.varint();
    return this.messageBody(type);
  }

  /** Reads the length and body of a message whose type was already read. */
  async messageBody(type: number): Promise<Message> {
    const len = new Reader(await this.exact(2)).u16();
    return parseMessage(type, await this.exact(len));
  }

  /** STOP_SENDING / cancel. */
  async cancel(reason?: unknown): Promise<void> {
    await this.reader.cancel(reason).catch(() => {});
  }
}

/** The stream ended (FIN) where more data was required. */
export class EndOfStream extends Error {
  constructor() {
    super("stream ended");
    this.name = "EndOfStream";
  }
}

/** Reads the rest of a SUBGROUP_HEADER after its type. */
export async function readSubgroupHeader(r: StreamReader, type: number): Promise<SubgroupHeader> {
  const f = subgroupHeaderFlags(type);
  const h: SubgroupHeader = {
    trackAlias: await r.varint(),
    group: await r.varint(),
    idMode: f.idMode,
    subgroupId: 0,
    properties: f.properties,
    endOfGroup: f.endOfGroup,
    firstObject: f.firstObject,
  };
  if (h.idMode === 2) h.subgroupId = await r.varint();
  if (f.hasPriority) h.priority = await r.u8();
  return h;
}

/** Decodes the Objects of a subgroup stream. */
export class SubgroupDecoder {
  private prev = -1;
  private r: StreamReader;
  readonly header: SubgroupHeader;
  constructor(r: StreamReader, header: SubgroupHeader) {
    this.r = r;
    this.header = header;
  }

  /** The next Object, or undefined at the clean end of the subgroup. */
  async next(): Promise<MoqObject | undefined> {
    if (await this.r.done()) return undefined;
    try {
      const delta = await this.r.varint();
      const id = this.prev < 0 ? delta : this.prev + delta + 1;
      this.prev = id;
      let properties: KeyValue[] | undefined;
      if (this.header.properties) {
        const n = await this.r.varint();
        if (n > MaxObjectProperties) throw protocolViolation(`object properties of ${n} bytes`);
        properties = readKeyValues(new Reader(await this.r.exact(n)));
      }
      const len = await this.r.varint();
      if (len === 0) {
        const status = await this.r.varint();
        if (status !== ObjectStatus.Normal && status !== ObjectStatus.EndOfGroup && status !== ObjectStatus.EndOfTrack) {
          throw protocolViolation(`object status ${status}`);
        }
        if (status !== ObjectStatus.Normal && properties?.length) throw protocolViolation("properties on non-Normal object");
        return { id, properties, status, payload: new Uint8Array() };
      }
      if (len > MaxObjectPayload) throw protocolViolation(`object payload of ${len} bytes`);
      return { id, properties, status: ObjectStatus.Normal, payload: await this.r.exact(len) };
    } catch (e) {
      if (e instanceof EndOfStream) throw protocolViolation("stream ended inside an object");
      throw e;
    }
  }
}
