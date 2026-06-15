import {
  ICredentialTestFunctions,
  IDataObject,
  IExecuteFunctions,
  INodeCredentialTestResult,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
  NodeOperationError,
} from 'n8n-workflow';

import {
  batchScan,
  getStats,
  instreamScan,
  monitorDirectory,
  parseScanResult,
  ping,
  scanFile,
  verifyLicenseKey,
} from './clamd';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function toBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value;
  return fallback;
}

// ---------------------------------------------------------------------------
// Node class
// ---------------------------------------------------------------------------

export class Clamav implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'ClamAV',
    name: 'clamAv',
    icon: 'fa:bug',
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["operation"]}}',
    description:
      'Scan files and content for viruses using a ClamAV clamd daemon. Free operations: Scan File, Scan Content, Get Stats. Premium operations (license key required): Batch Directory Scan, Real-time Monitor.',
    defaults: {
      name: 'ClamAV',
    },
    inputs: ['main'],
    outputs: ['main'],
    credentials: [
      {
        name: 'clamavApi',
        required: true,
        testedBy: 'testClamavConnection',
      },
    ],
    properties: [
      // ------------------------------------------------------------------ //
      // Operation selector
      // ------------------------------------------------------------------ //
      {
        displayName: 'Operation',
        name: 'operation',
        type: 'options',
        noDataExpression: true,
        options: [
          {
            name: 'Scan File',
            value: 'scanFile',
            description:
              'Scan a file by absolute path using the clamd SCAN command. The clamd process must have read access to the file.',
            action: 'Scan a file by path',
          },
          {
            name: 'Scan Content',
            value: 'scanContent',
            description:
              'Scan in-memory content (base64-encoded or raw string) using the clamd INSTREAM command.',
            action: 'Scan in-memory content',
          },
          {
            name: 'Get Stats',
            value: 'getStats',
            description: 'Retrieve clamd statistics including loaded signature counts using the STATS command.',
            action: 'Get clamd statistics',
          },
          {
            name: 'Batch Directory Scan (Premium)',
            value: 'batchScan',
            description:
              'Recursively scan all files in a directory. Requires a valid LowWatt Labs license key.',
            action: 'Batch scan a directory',
          },
          {
            name: 'Real-time Monitor (Premium)',
            value: 'monitorDirectory',
            description:
              'Watch a directory for file-system changes and scan each modified file in real time. Requires a valid LowWatt Labs license key.',
            action: 'Monitor directory for changes',
          },
        ],
        default: 'scanFile',
      },

      // ------------------------------------------------------------------ //
      // Scan File parameters
      // ------------------------------------------------------------------ //
      {
        displayName: 'File Path',
        name: 'filePath',
        type: 'string',
        required: true,
        default: '',
        placeholder: '/var/uploads/document.pdf',
        description:
          'Absolute path to the file to scan. The clamd daemon process must have filesystem read access to this path.',
        displayOptions: {
          show: {
            operation: ['scanFile'],
          },
        },
      },

      // ------------------------------------------------------------------ //
      // Scan Content parameters
      // ------------------------------------------------------------------ //
      {
        displayName: 'Content Encoding',
        name: 'contentEncoding',
        type: 'options',
        options: [
          { name: 'Base64', value: 'base64' },
          { name: 'UTF-8 String', value: 'utf8' },
          { name: 'n8n Binary Field', value: 'binary' },
        ],
        default: 'base64',
        description: 'How the content to scan is encoded',
        displayOptions: {
          show: {
            operation: ['scanContent'],
          },
        },
      },
      {
        displayName: 'Content',
        name: 'content',
        type: 'string',
        typeOptions: {
          rows: 4,
        },
        required: true,
        default: '',
        description: 'The content to scan, encoded as specified above',
        displayOptions: {
          show: {
            operation: ['scanContent'],
            contentEncoding: ['base64', 'utf8'],
          },
        },
      },
      {
        displayName: 'Binary Property Name',
        name: 'binaryProperty',
        type: 'string',
        required: true,
        default: 'data',
        description: 'Name of the n8n binary property containing the file bytes to scan',
        displayOptions: {
          show: {
            operation: ['scanContent'],
            contentEncoding: ['binary'],
          },
        },
      },

      // ------------------------------------------------------------------ //
      // Batch Directory Scan parameters (premium)
      // ------------------------------------------------------------------ //
      {
        displayName: 'Directory Path',
        name: 'directoryPath',
        type: 'string',
        required: true,
        default: '',
        placeholder: '/var/uploads',
        description: 'Absolute path to the directory to scan. Must be accessible to the clamd process.',
        displayOptions: {
          show: {
            operation: ['batchScan', 'monitorDirectory'],
          },
        },
      },
      {
        displayName: 'Recursive',
        name: 'recursive',
        type: 'boolean',
        default: true,
        description: 'Whether to scan subdirectories recursively',
        displayOptions: {
          show: {
            operation: ['batchScan'],
          },
        },
      },

      // ------------------------------------------------------------------ //
      // Monitor Directory parameters (premium)
      // ------------------------------------------------------------------ //
      {
        displayName: 'Monitor Duration (seconds)',
        name: 'monitorDuration',
        type: 'number',
        default: 30,
        description: 'How many seconds to watch the directory before returning results',
        displayOptions: {
          show: {
            operation: ['monitorDirectory'],
          },
        },
      },

      // ------------------------------------------------------------------ //
      // Shared options
      // ------------------------------------------------------------------ //
      {
        displayName: 'Options',
        name: 'options',
        type: 'collection',
        placeholder: 'Add option',
        default: {},
        options: [
          {
            displayName: 'Connection Timeout (ms)',
            name: 'timeoutMs',
            type: 'number',
            default: 30000,
            description: 'TCP connection and read timeout in milliseconds',
          },
          {
            displayName: 'Continue on Fail',
            name: 'continueOnFail',
            type: 'boolean',
            default: false,
            description:
              'Whether to continue executing subsequent items when a scan fails, appending error details to the output',
          },
        ],
      },
    ],
  };

  // -------------------------------------------------------------------------
  // Credential test method
  // -------------------------------------------------------------------------

  methods = {
    credentialTest: {
      async testClamavConnection(
        this: ICredentialTestFunctions,
        credential: Parameters<ICredentialTestFunctions['helpers']['request']>[0] extends never
          ? never
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          : any,
      ): Promise<INodeCredentialTestResult> {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const creds = credential.data as any;
        try {
          const alive = await ping(
            (creds.host as string) || 'localhost',
            (creds.port as number) || 3310,
            5000,
          );
          if (alive) {
            return { status: 'OK', message: 'Successfully connected to clamd (PING → PONG).' };
          }
          return { status: 'Error', message: 'clamd did not respond to PING.' };
        } catch (err) {
          return {
            status: 'Error',
            message: `Connection failed: ${(err as Error).message}`,
          };
        }
      },
    },
  };

  // -------------------------------------------------------------------------
  // Execute
  // -------------------------------------------------------------------------

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];

    const credentials = await this.getCredentials('clamavApi');
    const host = (credentials.host as string) || 'localhost';
    const port = (credentials.port as number) || 3310;
    const licenseKey = (credentials.licenseKey as string) || '';

    for (let i = 0; i < items.length; i++) {
      const operation = this.getNodeParameter('operation', i) as string;
      const options = this.getNodeParameter('options', i, {}) as IDataObject;
      const timeoutMs = (options.timeoutMs as number | undefined) ?? 30_000;

      try {
        // ---------------------------------------------------------------- //
        // FREE OPERATIONS
        // ---------------------------------------------------------------- //

        if (operation === 'scanFile') {
          const filePath = this.getNodeParameter('filePath', i) as string;
          const raw = await scanFile(host, port, filePath, timeoutMs);
          const result = parseScanResult(raw);
          returnData.push({
            json: {
              operation,
              ...result,
            },
          });

          // ---------------------------------------------------------------- //
        } else if (operation === 'scanContent') {
          const encoding = this.getNodeParameter('contentEncoding', i) as string;
          let dataBuffer: Buffer;

          if (encoding === 'binary') {
            const binaryProperty = this.getNodeParameter('binaryProperty', i) as string;
            const binaryData = this.helpers.assertBinaryData(i, binaryProperty);
            dataBuffer = await this.helpers.getBinaryDataBuffer(i, binaryProperty);
            void binaryData; // type-checked above
          } else if (encoding === 'base64') {
            const content = this.getNodeParameter('content', i) as string;
            dataBuffer = Buffer.from(content, 'base64');
          } else {
            // utf8
            const content = this.getNodeParameter('content', i) as string;
            dataBuffer = Buffer.from(content, 'utf8');
          }

          const raw = await instreamScan(host, port, dataBuffer, timeoutMs);
          const result = parseScanResult(raw);
          returnData.push({
            json: {
              operation,
              ...result,
            },
          });

          // ---------------------------------------------------------------- //
        } else if (operation === 'getStats') {
          const raw = await getStats(host, port, timeoutMs);
          returnData.push({
            json: {
              operation,
              stats: raw,
            },
          });

          // ---------------------------------------------------------------- //
          // PREMIUM OPERATIONS
          // ---------------------------------------------------------------- //
        } else if (operation === 'batchScan') {
          const valid = await verifyLicenseKey(licenseKey);
          if (!valid) {
            throw new NodeOperationError(
              this.getNode(),
              'Premium feature: a valid LowWatt Labs license key is required for Batch Directory Scan. Set it in the ClamAV credentials.',
              { itemIndex: i },
            );
          }

          const directoryPath = this.getNodeParameter('directoryPath', i) as string;
          const recursive = toBoolean(this.getNodeParameter('recursive', i, true), true);

          const entries = await batchScan(host, port, directoryPath, recursive, timeoutMs);

          for (const entry of entries) {
            returnData.push({
              json: {
                operation,
                ...entry.result,
                file: entry.file,
              },
            });
          }

          // ---------------------------------------------------------------- //
        } else if (operation === 'monitorDirectory') {
          const valid = await verifyLicenseKey(licenseKey);
          if (!valid) {
            throw new NodeOperationError(
              this.getNode(),
              'Premium feature: a valid LowWatt Labs license key is required for Real-time Monitor. Set it in the ClamAV credentials.',
              { itemIndex: i },
            );
          }

          const directoryPath = this.getNodeParameter('directoryPath', i) as string;
          const durationSec = this.getNodeParameter('monitorDuration', i, 30) as number;
          const durationMs = Math.max(1, durationSec) * 1000;

          const monitorEvents = await monitorDirectory(
            host,
            port,
            directoryPath,
            durationMs,
            timeoutMs,
          );

          for (const event of monitorEvents) {
            returnData.push({
              json: {
                operation,
                timestamp: event.timestamp,
                changeType: event.changeType,
                file: event.file,
                ...event.result,
              },
            });
          }

          if (monitorEvents.length === 0) {
            returnData.push({
              json: {
                operation,
                message: `No file-system change events detected in ${durationSec}s.`,
                eventsDetected: 0,
              },
            });
          }

          // ---------------------------------------------------------------- //
        } else {
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`, {
            itemIndex: i,
          });
        }
      } catch (error) {
        const continueOnFail =
          toBoolean(options.continueOnFail, false) || this.continueOnFail();
        if (continueOnFail) {
          returnData.push({
            json: {
              operation,
              error: (error as Error).message,
            },
            pairedItem: { item: i },
          });
          continue;
        }
        if (error instanceof NodeOperationError) throw error;
        throw new NodeOperationError(this.getNode(), error as Error, { itemIndex: i });
      }
    }

    return [returnData];
  }
}
