import {
  IAuthenticateGeneric,
  ICredentialTestRequest,
  ICredentialType,
  INodeProperties,
} from 'n8n-workflow';

export class ClamavApi implements ICredentialType {
  name = 'clamavApi';
  displayName = 'ClamAV API';
  documentationUrl = 'https://www.clamav.net/documents/configuration#clamdconf';

  properties: INodeProperties[] = [
    {
      displayName: 'Host',
      name: 'host',
      type: 'string',
      default: 'localhost',
      placeholder: 'localhost',
      description: 'Hostname or IP address of the clamd daemon',
      required: true,
    },
    {
      displayName: 'Port',
      name: 'port',
      type: 'number',
      default: 3310,
      description: 'TCP port clamd listens on (default: 3310)',
      required: true,
    },
    {
      displayName: 'License Key (Premium)',
      name: 'licenseKey',
      type: 'string',
      typeOptions: {
        password: true,
      },
      default: '',
      description:
        'LowWatt Labs license key required for premium operations: Batch Directory Scan and Real-time Monitor. Leave blank for free-tier operations (Scan File, Scan Content, Get Stats).',
      required: false,
    },
  ];

  // n8n will attempt a PING to test credentials
  test: ICredentialTestRequest = {
    request: {
      // No HTTP — custom test is performed in the node via the built-in
      // credential-test method defined in Clamav.node.ts
      baseURL: '={{$credentials.host}}',
      url: '',
    },
  };

  authenticate: IAuthenticateGeneric = {
    type: 'generic',
    properties: {},
  };
}
