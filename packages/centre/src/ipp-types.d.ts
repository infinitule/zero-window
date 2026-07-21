/**
 * Minimal, strict ambient typings for the subset of the `ipp` package used by
 * ZERO-WINDOW (client execution plus parse/serialize, which the tests use to
 * run a real IPP wire-format responder in-process).
 */
declare module "ipp" {
  export type IppAttributeValue =
    | string
    | number
    | boolean
    | Date
    | Buffer
    | IppAttributeValue[];

  export interface IppGroup {
    [attribute: string]: IppAttributeValue;
  }

  export interface IppRequest {
    "operation-attributes-tag"?: IppGroup;
    "job-attributes-tag"?: IppGroup | IppGroup[];
    "printer-attributes-tag"?: IppGroup;
    data?: Buffer;
    version?: string;
    operation?: string | number;
    statusCode?: string;
    id?: number;
  }

  export interface IppResponse {
    version: string;
    statusCode: string;
    id: number;
    "operation-attributes-tag"?: IppGroup;
    "job-attributes-tag"?: IppGroup | IppGroup[];
    "printer-attributes-tag"?: IppGroup;
    data?: Buffer;
  }

  export interface PrinterInstance {
    execute(
      operation: string,
      message: IppRequest | null,
      callback: (error: Error | null, response: IppResponse) => void,
    ): void;
  }

  export function Printer(url: string, options?: { version?: string; charset?: string }): PrinterInstance;
  export function parse(buffer: Buffer): IppRequest;
  export function serialize(message: IppRequest): Buffer;
}
