/**
 * Akash Console API — Zod Schema Registry
 *
 * Self-contained collection of all Zod schemas from the console API's http-schema
 * layer, organized by domain. These are proto-compatible (no transforms/refinements
 * on base types) and serve as the source of truth for proto generation.
 *
 * Source: ~/console/apps/api/src/<module>/http-schemas/
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

/** Deployment sequence number — represented as a string for proto compat. */
export const DseqSchema = z.string().describe("Deployment sequence number");

/** Bech32 Akash address (akash1...). */
export const AkashAddressSchema = z.string().describe("Akash bech32 address");

export const BalanceSchema = z.object({
  denom: z.string(),
  amount: z.string(),
});

export const AttributeSchema = z.object({
  key: z.string(),
  value: z.string(),
});

export const EscrowIdSchema = z.object({
  scope: z.string(),
  xid: z.string(),
});

export const EscrowDepositSchema = z.object({
  owner: z.string(),
  height: z.string(),
  source: z.string(),
  balance: BalanceSchema,
});

export const EscrowAccountSchema = z.object({
  id: EscrowIdSchema,
  state: z.object({
    owner: z.string(),
    state: z.string(),
    transferred: z.array(BalanceSchema),
    settled_at: z.string(),
    funds: z.array(BalanceSchema),
    deposits: z.array(EscrowDepositSchema),
  }),
});

// ---------------------------------------------------------------------------
// Auth — API Keys
// source: auth/http-schemas/api-key.schema.ts
// ---------------------------------------------------------------------------

export const ApiKeyHiddenSchema = z.object({
  id: z.string(),
  name: z.string(),
  expiresAt: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
  lastUsedAt: z.string().nullable(),
  keyFormat: z.string(),
});

export const ApiKeyVisibleSchema = ApiKeyHiddenSchema.extend({
  apiKey: z.string(),
});

export const CreateApiKeyRequestSchema = z.object({
  data: z.object({
    name: z.string(),
    expiresAt: z.string().optional(),
  }),
});

export const UpdateApiKeyRequestSchema = z.object({
  data: z.object({
    name: z.string().optional(),
  }),
});

export const FindApiKeyParamsSchema = z.object({
  id: z.string(),
});

export const ListApiKeysResponseSchema = z.object({
  data: z.array(ApiKeyHiddenSchema),
});

export const ApiKeyVisibleResponseSchema = z.object({
  data: ApiKeyVisibleSchema,
});

export const ApiKeyHiddenResponseSchema = z.object({
  data: ApiKeyHiddenSchema,
});

// ---------------------------------------------------------------------------
// Auth — Verify Email
// source: auth/http-schemas/verify-email.schema.ts
// ---------------------------------------------------------------------------

export const VerifyEmailQuerySchema = z.object({
  token: z.string(),
});

// ---------------------------------------------------------------------------
// Bid
// source: bid/http-schemas/bid.schema.ts
// ---------------------------------------------------------------------------

const BidResourcesV3Schema = z.object({
  cpu: z.object({
    units: z.object({ val: z.string() }),
    attributes: z.array(AttributeSchema),
  }),
  gpu: z.object({
    units: z.object({ val: z.string() }),
    attributes: z.array(AttributeSchema),
  }),
  memory: z.object({
    quantity: z.object({ val: z.string() }),
    attributes: z.array(AttributeSchema),
  }),
  storage: z.array(
    z.object({
      name: z.string(),
      quantity: z.object({ val: z.string() }),
      attributes: z.array(AttributeSchema),
    })
  ),
  endpoints: z.array(
    z.object({
      kind: z.string(),
      sequence_number: z.number(),
    })
  ),
});

export const BidResponseSchema = z.object({
  bid: z.object({
    id: z.object({
      owner: z.string(),
      dseq: DseqSchema,
      gseq: z.number(),
      oseq: z.number(),
      provider: z.string(),
      bseq: z.number(),
    }),
    state: z.string(),
    price: BalanceSchema,
    created_at: z.string(),
    resources_offer: z.array(
      z.object({
        resources: BidResourcesV3Schema,
        count: z.number(),
      })
    ),
  }),
  escrow_account: EscrowAccountSchema,
  isCertificateRequired: z.boolean(),
});

export const ListBidsQuerySchema = z.object({
  dseq: DseqSchema,
});

export const ListBidsResponseSchema = z.object({
  data: z.array(BidResponseSchema),
});

// ---------------------------------------------------------------------------
// Certificate
// source: certificate/http-schemas/create-certificate.schema.ts
// ---------------------------------------------------------------------------

export const CreateCertificateResponseSchema = z.object({
  data: z.object({
    certPem: z.string(),
    pubkeyPem: z.string(),
    encryptedKey: z.string(),
  }),
});

// ---------------------------------------------------------------------------
// Deployment
// source: deployment/http-schemas/deployment.schema.ts
// ---------------------------------------------------------------------------

export const LeaseServiceStatusSchema = z.object({
  name: z.string(),
  available: z.number(),
  total: z.number(),
  uris: z.array(z.string()),
  observed_generation: z.number(),
  replicas: z.number(),
  updated_replicas: z.number(),
  ready_replicas: z.number(),
  available_replicas: z.number(),
});

export const ForwardedPortSchema = z.object({
  port: z.number(),
  externalPort: z.number(),
  host: z.string().optional(),
  available: z.number().optional(),
});

export const IpSchema = z.object({
  IP: z.string(),
  Port: z.number(),
  ExternalPort: z.number(),
  Protocol: z.string(),
});

export const LeaseStatusResponseSchema = z.object({
  forwarded_ports: z.record(z.string(), z.array(ForwardedPortSchema)),
  ips: z.record(z.string(), z.array(IpSchema)),
  services: z.record(z.string(), LeaseServiceStatusSchema),
});

const DeploymentLeaseSchema = z.object({
  id: z.object({
    owner: z.string(),
    dseq: DseqSchema,
    gseq: z.number(),
    oseq: z.number(),
    provider: z.string(),
    bseq: z.number(),
  }),
  state: z.string(),
  price: BalanceSchema,
  created_at: z.string(),
  closed_on: z.string(),
  reason: z.string().optional(),
  status: LeaseStatusResponseSchema.nullable(),
});

export const DeploymentResponseSchema = z.object({
  deployment: z.object({
    id: z.object({
      owner: z.string(),
      dseq: DseqSchema,
    }),
    state: z.string(),
    hash: z.string(),
    created_at: z.string(),
  }),
  leases: z.array(DeploymentLeaseSchema),
  escrow_account: z.object({
    id: EscrowIdSchema,
    state: z.object({
      owner: z.string(),
      state: z.string(),
      transferred: z.array(BalanceSchema),
      settled_at: z.string(),
      funds: z.array(BalanceSchema),
      deposits: z.array(EscrowDepositSchema),
    }),
  }),
});

export const GetDeploymentResponseSchema = z.object({
  data: DeploymentResponseSchema,
});

export const GetDeploymentParamsSchema = z.object({
  dseq: DseqSchema,
});

export const CreateDeploymentRequestSchema = z.object({
  data: z.object({
    sdl: z.string(),
    deposit: z.number(),
  }),
});

export const CreateDeploymentResponseSchema = z.object({
  data: z.object({
    dseq: DseqSchema,
    manifest: z.string(),
    signTx: z.object({
      type: z.string(),
      data: z.string(),
    }),
  }),
});

export const CloseDeploymentParamsSchema = z.object({
  dseq: DseqSchema,
});

export const CloseDeploymentResponseSchema = z.object({
  data: z.object({
    success: z.boolean(),
  }),
});

export const DepositDeploymentRequestSchema = z.object({
  data: z.object({
    dseq: DseqSchema,
    deposit: z.number(),
  }),
});

export const DepositDeploymentResponseSchema = z.object({
  data: DeploymentResponseSchema,
});

export const UpdateDeploymentRequestSchema = z.object({
  data: z.object({
    sdl: z.string(),
    certificate: z
      .object({
        certPem: z.string(),
        keyPem: z.string(),
      })
      .optional(),
  }),
});

export const UpdateDeploymentResponseSchema = z.object({
  data: DeploymentResponseSchema,
});

export const ListDeploymentsQuerySchema = z.object({
  skip: z.number().optional(),
  limit: z.number().optional(),
});

export const ListDeploymentsResponseSchema = z.object({
  data: z.object({
    deployments: z.array(DeploymentResponseSchema),
    pagination: z.object({
      total: z.number(),
      skip: z.number(),
      limit: z.number(),
      hasMore: z.boolean(),
    }),
  }),
});

export const ListWithResourcesParamsSchema = z.object({
  address: AkashAddressSchema,
  skip: z.number(),
  limit: z.number(),
});

export const ListWithResourcesQuerySchema = z.object({
  status: z.enum(["active", "closed"]).optional(),
  reverseSorting: z.boolean().optional(),
});

export const ListWithResourcesResponseSchema = z.object({
  count: z.number(),
  results: z.array(
    z.object({
      owner: z.string(),
      dseq: DseqSchema,
      status: z.string(),
      createdHeight: z.number(),
      cpuUnits: z.number(),
      gpuUnits: z.number(),
      memoryQuantity: z.number(),
      storageQuantity: z.number(),
      leases: z.array(
        z.object({
          id: z.string(),
          owner: z.string(),
          provider: z
            .object({
              address: z.string(),
              hostUri: z.string(),
            })
            .optional(),
          dseq: DseqSchema,
          gseq: z.number(),
          oseq: z.number(),
          state: z.string(),
          price: BalanceSchema,
        })
      ),
    })
  ),
});

export const GetDeploymentByOwnerDseqParamsSchema = z.object({
  owner: AkashAddressSchema,
  dseq: DseqSchema,
});

export const GetDeploymentByOwnerDseqResponseSchema = z.object({
  owner: z.string(),
  dseq: DseqSchema,
  balance: z.number(),
  denom: z.string(),
  status: z.string(),
  totalMonthlyCostUDenom: z.number(),
  leases: z.array(
    z.object({
      gseq: z.number(),
      oseq: z.number(),
      provider: z
        .object({
          address: z.string(),
          hostUri: z.string(),
          isDeleted: z.boolean(),
          attributes: z.array(AttributeSchema),
        })
        .nullable(),
      status: z.string(),
      monthlyCostUDenom: z.number(),
      cpuUnits: z.number(),
      gpuUnits: z.number(),
      memoryQuantity: z.number(),
      storageQuantity: z.number(),
    })
  ),
  events: z.array(
    z.object({
      txHash: z.string(),
      date: z.string(),
      type: z.string(),
    })
  ),
});

export const GetWeeklyDeploymentCostResponseSchema = z.object({
  data: z.object({
    weeklyCost: z.number(),
  }),
});

// ---------------------------------------------------------------------------
// Deployment — RPC / fallback node schemas
// source: deployment/http-schemas/deployment-rpc.schema.ts
// ---------------------------------------------------------------------------

export const FallbackDeploymentListQuerySchema = z.object({
  "filters.owner": z.string().optional(),
  "filters.state": z.enum(["active", "closed"]).optional(),
  "pagination.offset": z.number().optional(),
  "pagination.limit": z.number().optional(),
  "pagination.key": z.string().optional(),
  "pagination.count_total": z.boolean().optional(),
  "pagination.reverse": z.boolean().optional(),
});

export const FallbackDeploymentListResponseSchema = z.object({
  deployments: z.array(
    z.object({
      deployment: z.object({
        id: z.object({ owner: z.string(), dseq: DseqSchema }),
        state: z.string(),
        hash: z.string(),
        created_at: z.string(),
      }),
      groups: z.array(
        z.object({
          id: z.object({
            owner: z.string(),
            dseq: DseqSchema,
            gseq: z.number(),
          }),
          state: z.string(),
          group_spec: z.object({
            name: z.string(),
            requirements: z.object({
              signed_by: z.object({
                all_of: z.array(z.string()),
                any_of: z.array(z.string()),
              }),
              attributes: z.array(AttributeSchema),
            }),
            resources: z.array(
              z.object({
                resource: z.object({
                  id: z.number(),
                  cpu: z.object({
                    units: z.object({ val: z.string() }),
                    attributes: z.array(AttributeSchema),
                  }),
                  memory: z.object({
                    quantity: z.object({ val: z.string() }),
                    attributes: z.array(AttributeSchema),
                  }),
                  storage: z.array(
                    z.object({
                      name: z.string(),
                      quantity: z.object({ val: z.string() }),
                      attributes: z.array(AttributeSchema),
                    })
                  ),
                  gpu: z.object({
                    units: z.object({ val: z.string() }),
                    attributes: z.array(AttributeSchema),
                  }),
                  endpoints: z.array(
                    z.object({
                      kind: z.string(),
                      sequence_number: z.number(),
                    })
                  ),
                }),
                count: z.number(),
                price: BalanceSchema,
              })
            ),
          }),
          created_at: z.string(),
        })
      ),
      escrow_account: EscrowAccountSchema,
    })
  ),
  pagination: z.object({
    next_key: z.string().nullable(),
    total: z.string(),
  }),
});

export const FallbackDeploymentInfoQuerySchema = z.object({
  "id.owner": z.string(),
  "id.dseq": z.string(),
});

// ---------------------------------------------------------------------------
// Deployment — Lease RPC
// source: deployment/http-schemas/lease-rpc.schema.ts
// ---------------------------------------------------------------------------

export const CreateLeaseRequestSchema = z.object({
  manifest: z.string(),
  certificate: z
    .object({
      certPem: z.string(),
      keyPem: z.string(),
    })
    .optional(),
  leases: z.array(
    z.object({
      dseq: DseqSchema,
      gseq: z.number(),
      oseq: z.number(),
      provider: AkashAddressSchema,
    })
  ),
});

// ---------------------------------------------------------------------------
// Deployment — Settings
// source: deployment/http-schemas/deployment-setting.schema.ts
// ---------------------------------------------------------------------------

export const GetDeploymentSettingParamsSchema = z.object({
  dseq: DseqSchema,
});

export const DeploymentSettingSchema = z.object({
  dseq: DseqSchema,
  autoTopUpEnabled: z.boolean(),
});

export const UpdateDeploymentSettingRequestSchema = z.object({
  data: z.object({
    autoTopUpEnabled: z.boolean(),
  }),
});

// ---------------------------------------------------------------------------
// Provider
// source: provider/http-schemas/provider.schema.ts
// ---------------------------------------------------------------------------

const ProviderGpuModelSchema = z.object({
  vendor: z.string(),
  model: z.string(),
  ram: z.string(),
  interface: z.string(),
});

const ProviderAttributeSchema = z.object({
  key: z.string(),
  value: z.string(),
  auditedBy: z.array(z.string()),
});

export const ProviderListQuerySchema = z.object({
  scope: z.enum(["all", "trial"]).default("all"),
});

export const ProviderListResponseSchema = z.array(
  z.object({
    owner: z.string(),
    name: z.string().nullable(),
    hostUri: z.string(),
    createdHeight: z.number(),
    email: z.string().nullable().optional(),
    website: z.string().nullable().optional(),
    lastCheckDate: z.string().nullable().optional(),
    deploymentCount: z.number().nullable().optional(),
    leaseCount: z.number().nullable().optional(),
    cosmosSdkVersion: z.string(),
    akashVersion: z.string(),
    ipRegion: z.string().nullable(),
    ipRegionCode: z.string().nullable(),
    ipCountry: z.string().nullable(),
    ipCountryCode: z.string().nullable(),
    ipLat: z.string().nullable(),
    ipLon: z.string().nullable(),
    uptime1d: z.number().nullable(),
    uptime7d: z.number().nullable(),
    uptime30d: z.number().nullable(),
    isValidVersion: z.boolean(),
    isOnline: z.boolean(),
    lastOnlineDate: z.string().nullable(),
    isAudited: z.boolean(),
    gpuModels: z.array(ProviderGpuModelSchema),
    attributes: z.array(ProviderAttributeSchema),
    host: z.string().nullable(),
    organization: z.string().nullable(),
    statusPage: z.string().nullable(),
    locationRegion: z.string().nullable(),
    country: z.string().nullable(),
    city: z.string().nullable(),
    timezone: z.string().nullable(),
    locationType: z.string().nullable(),
    hostingProvider: z.string().nullable(),
    hardwareCpu: z.string().nullable(),
    hardwareCpuArch: z.string().nullable(),
    hardwareGpuVendor: z.string().nullable(),
    hardwareGpuModels: z.array(z.string()).nullable(),
    hardwareDisk: z.array(z.string()).nullable(),
    featPersistentStorage: z.boolean(),
    featPersistentStorageType: z.array(z.string()).nullable(),
    hardwareMemory: z.string().nullable(),
    networkProvider: z.string().nullable(),
    networkSpeedDown: z.number(),
    networkSpeedUp: z.number(),
    tier: z.string().nullable(),
    featEndpointCustomDomain: z.boolean(),
    workloadSupportChia: z.boolean(),
    workloadSupportChiaCapabilities: z.array(z.string()).nullable(),
    featEndpointIp: z.boolean(),
  })
);

export const ProviderParamsSchema = z.object({
  address: z.string(),
});

const ProviderStatsItemSchema = z.object({
  active: z.number(),
  available: z.number(),
  pending: z.number(),
});

export const ProviderResponseSchema = z.object({
  owner: z.string(),
  name: z.string().nullable(),
  hostUri: z.string(),
  createdHeight: z.number(),
  email: z.string().nullable(),
  website: z.string().nullable(),
  lastCheckDate: z.string().nullable(),
  deploymentCount: z.number(),
  leaseCount: z.number(),
  cosmosSdkVersion: z.string(),
  akashVersion: z.string(),
  ipRegion: z.string().nullable(),
  ipRegionCode: z.string().nullable(),
  ipCountry: z.string().nullable(),
  ipCountryCode: z.string().nullable(),
  ipLat: z.string().nullable(),
  ipLon: z.string().nullable(),
  uptime1d: z.number(),
  uptime7d: z.number(),
  uptime30d: z.number(),
  isValidVersion: z.boolean(),
  isOnline: z.boolean(),
  lastOnlineDate: z.string().nullable(),
  isAudited: z.boolean(),
  stats: z.object({
    cpu: ProviderStatsItemSchema,
    gpu: ProviderStatsItemSchema,
    memory: ProviderStatsItemSchema,
    storage: z.object({
      ephemeral: ProviderStatsItemSchema,
      persistent: ProviderStatsItemSchema,
    }),
  }),
  gpuModels: z.array(ProviderGpuModelSchema),
  attributes: z.array(ProviderAttributeSchema),
  host: z.string().nullable(),
  organization: z.string().nullable(),
  statusPage: z.string().nullable(),
  locationRegion: z.string().nullable(),
  country: z.string().nullable(),
  city: z.string().nullable(),
  timezone: z.string().nullable(),
  locationType: z.string().nullable(),
  hostingProvider: z.string().nullable(),
  hardwareCpu: z.string().nullable(),
  hardwareCpuArch: z.string().nullable(),
  hardwareGpuVendor: z.string().nullable(),
  hardwareGpuModels: z.array(z.string()),
  hardwareDisk: z.array(z.string()),
  featPersistentStorage: z.boolean(),
  featPersistentStorageType: z.array(z.string()),
  hardwareMemory: z.string().nullable(),
  networkProvider: z.string().nullable(),
  networkSpeedDown: z.number(),
  networkSpeedUp: z.number(),
  tier: z.string().nullable(),
  featEndpointCustomDomain: z.boolean(),
  workloadSupportChia: z.boolean(),
  workloadSupportChiaCapabilities: z.array(z.string()),
  featEndpointIp: z.boolean(),
  uptime: z.array(
    z.object({
      id: z.string(),
      isOnline: z.boolean(),
      checkDate: z.string(),
    })
  ),
});

export const ProviderActiveLeasesGraphDataParamsSchema = z.object({
  providerAddress: AkashAddressSchema,
});

export const ProviderActiveLeasesGraphDataResponseSchema = z.object({
  currentValue: z.number(),
  compareValue: z.number(),
  snapshots: z.array(
    z.object({
      date: z.string(),
      value: z.number(),
    })
  ),
  now: z.object({ count: z.number() }),
  compare: z.object({ count: z.number() }),
});

// ---------------------------------------------------------------------------
// Provider — Auditor
// source: provider/http-schemas/auditor.schema.ts
// ---------------------------------------------------------------------------

export const AuditorParamsSchema = z.object({
  address: z.string(),
});

// ---------------------------------------------------------------------------
// Provider — JWT Token
// source: provider/http-schemas/jwt-token.schema.ts
// ---------------------------------------------------------------------------

export const GetJwtTokenRequestSchema = z.object({
  provider: z.string(),
});

export const GetJwtTokenResponseSchema = z.object({
  data: z.object({
    token: z.string(),
  }),
});

// ---------------------------------------------------------------------------
// Network
// source: network/http-schemas/network.schema.ts
// ---------------------------------------------------------------------------

export const GetNodesParamsSchema = z.object({
  network: z.enum(["mainnet", "testnet", "sandbox"]),
});

export const NodeSchema = z.object({
  id: z.string(),
  api: z.string(),
  rpc: z.string(),
});

export const GetNodesResponseSchema = z.array(NodeSchema);

// ---------------------------------------------------------------------------
// Pricing
// source: pricing/http-schemas/pricing.schema.ts
// ---------------------------------------------------------------------------

export const PricingSpecsSchema = z.object({
  cpu: z.number(),
  memory: z.number(),
  storage: z.number(),
});

const PricingCalculationSchema = z.object({
  spec: PricingSpecsSchema,
  akash: z.number(),
  aws: z.number(),
  gcp: z.number(),
  azure: z.number(),
});

export const PricingResponseSchema = z.array(PricingCalculationSchema);

// ---------------------------------------------------------------------------
// Address
// source: address/http-schemas/address.schema.ts
// ---------------------------------------------------------------------------

export const ValidatorSchema = z.object({
  address: z.string().optional(),
  moniker: z.string().optional(),
  operatorAddress: z.string().optional(),
  avatarUrl: z.string().optional(),
});

export const DelegationSchema = z.object({
  validator: ValidatorSchema,
  amount: z.number(),
  reward: z.number().nullable(),
});

export const AssetSchema = z.object({
  symbol: z.string().optional(),
  ibcToken: z.string().optional(),
  logoUrl: z.string().optional(),
  description: z.string().optional(),
  amount: z.number(),
});

export const RedelegationSchema = z.object({
  srcAddress: ValidatorSchema,
  dstAddress: ValidatorSchema,
  creationHeight: z.number(),
  completionTime: z.string(),
  amount: z.number(),
});

export const TransactionMessageSchema = z.object({
  id: z.string(),
  type: z.string(),
  amount: z.number(),
  isReceiver: z.boolean(),
});

export const TransactionSchema = z.object({
  height: z.number(),
  datetime: z.string(),
  hash: z.string(),
  isSuccess: z.boolean(),
  error: z.string().nullable(),
  gasUsed: z.number(),
  gasWanted: z.number(),
  fee: z.number(),
  memo: z.string().nullable(),
  isSigner: z.boolean(),
  messages: z.array(TransactionMessageSchema),
});

export const GetAddressParamsSchema = z.object({
  address: AkashAddressSchema,
});

export const GetAddressResponseSchema = z.object({
  total: z.number(),
  delegations: z.array(DelegationSchema),
  available: z.number(),
  delegated: z.number(),
  rewards: z.number(),
  assets: z.array(AssetSchema),
  redelegations: z.array(RedelegationSchema),
  commission: z.number(),
  latestTransactions: z.array(TransactionSchema),
});

export const GetAddressTransactionsParamsSchema = z.object({
  address: AkashAddressSchema,
  skip: z.number(),
  limit: z.number(),
});

export const GetAddressTransactionsResponseSchema = z.object({
  count: z.number(),
  results: z.array(TransactionSchema),
});

// ---------------------------------------------------------------------------
// Consolidated export map — used by generate-proto.ts
// ---------------------------------------------------------------------------

export const ALL_SCHEMAS = {
  // Auth
  ApiKeyHiddenSchema,
  ApiKeyVisibleSchema,
  CreateApiKeyRequestSchema,
  UpdateApiKeyRequestSchema,
  FindApiKeyParamsSchema,
  ListApiKeysResponseSchema,
  ApiKeyVisibleResponseSchema,
  ApiKeyHiddenResponseSchema,
  // Bid
  BidResponseSchema,
  ListBidsQuerySchema,
  ListBidsResponseSchema,
  // Certificate
  CreateCertificateResponseSchema,
  // Deployment
  DeploymentResponseSchema,
  GetDeploymentResponseSchema,
  GetDeploymentParamsSchema,
  CreateDeploymentRequestSchema,
  CreateDeploymentResponseSchema,
  CloseDeploymentParamsSchema,
  CloseDeploymentResponseSchema,
  DepositDeploymentRequestSchema,
  DepositDeploymentResponseSchema,
  UpdateDeploymentRequestSchema,
  UpdateDeploymentResponseSchema,
  ListDeploymentsQuerySchema,
  ListDeploymentsResponseSchema,
  ListWithResourcesParamsSchema,
  ListWithResourcesQuerySchema,
  ListWithResourcesResponseSchema,
  GetDeploymentByOwnerDseqParamsSchema,
  GetDeploymentByOwnerDseqResponseSchema,
  GetWeeklyDeploymentCostResponseSchema,
  // Deployment — RPC
  FallbackDeploymentListQuerySchema,
  FallbackDeploymentListResponseSchema,
  FallbackDeploymentInfoQuerySchema,
  // Deployment — Lease
  CreateLeaseRequestSchema,
  LeaseStatusResponseSchema,
  // Deployment — Settings
  GetDeploymentSettingParamsSchema,
  DeploymentSettingSchema,
  UpdateDeploymentSettingRequestSchema,
  // Provider
  ProviderListQuerySchema,
  ProviderListResponseSchema,
  ProviderParamsSchema,
  ProviderResponseSchema,
  ProviderActiveLeasesGraphDataParamsSchema,
  ProviderActiveLeasesGraphDataResponseSchema,
  // Provider — JWT
  GetJwtTokenRequestSchema,
  GetJwtTokenResponseSchema,
  // Network
  GetNodesParamsSchema,
  NodeSchema,
  GetNodesResponseSchema,
  // Pricing
  PricingSpecsSchema,
  PricingResponseSchema,
  // Address
  GetAddressParamsSchema,
  GetAddressResponseSchema,
  GetAddressTransactionsParamsSchema,
  GetAddressTransactionsResponseSchema,
} as const;

// Re-export Zod types for downstream use
export type { z };

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log("Akash Console API — Schema Registry");
  console.log(`Total exported schemas: ${Object.keys(ALL_SCHEMAS).length}`);
  for (const name of Object.keys(ALL_SCHEMAS)) {
    console.log(`  ✓ ${name}`);
  }
}
