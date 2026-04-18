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


// ═══════════════════════════════════════════════════════════════════════════
// BILLING / WALLET / STRIPE (extracted from console/apps/api/src/billing/)
// ═══════════════════════════════════════════════════════════════════════════

const WalletOutputInnerSchema = z.object({
  id: z.number().nullable(),
  userId: z.string().nullable(),
  creditAmount: z.number(),
  address: z.string().nullable(),
  denom: z.string(),
  isTrialing: z.boolean(),
  createdAt: z.string().nullable(),
  requires3DS: z.boolean().optional(),
  clientSecret: z.string().nullable().optional(),
  paymentIntentId: z.string().nullable().optional(),
  paymentMethodId: z.string().nullable().optional(),
});

export const WalletResponseOutputSchema = z.object({ data: WalletOutputInnerSchema });
export const WalletListResponseOutputSchema = z.object({ data: z.array(WalletOutputInnerSchema) });
export const StartTrialRequestInputSchema = z.object({ data: z.object({ userId: z.string() }) });
export const WalletSettingsSchema = z.object({ autoReloadEnabled: z.boolean() });
export const WalletSettingsResponseSchema = z.object({ data: z.object({ autoReloadEnabled: z.boolean() }) });
export const CreateWalletSettingsRequestSchema = z.object({ data: z.object({ autoReloadEnabled: z.boolean() }) });

export const SetupIntentResponseSchema = z.object({ data: z.object({ clientSecret: z.string().nullable() }) });

export const PaymentMethodSchema = z.object({
  type: z.string(),
  validated: z.boolean().optional(),
  isDefault: z.boolean().optional(),
  card: z.object({
    brand: z.string().nullable(), last4: z.string().nullable(),
    exp_month: z.number(), exp_year: z.number(),
    funding: z.string().nullable().optional(),
    country: z.string().nullable().optional(),
    network: z.string().nullable().optional(),
  }).nullable().optional(),
  link: z.object({ email: z.string().nullable().optional() }).nullable().optional(),
});
export const PaymentMethodsResponseSchema = z.object({ data: z.array(PaymentMethodSchema) });
export const PaymentMethodMarkAsDefaultInputSchema = z.object({ data: z.object({ id: z.string() }) });

export const ConfirmPaymentRequestSchema = z.object({
  data: z.object({
    userId: z.string(), paymentMethodId: z.string(),
    amount: z.number(), currency: z.string(),
    awaitResolved: z.boolean().optional(),
  }),
});

export const PaymentIntentResultSchema = z.object({
  success: z.boolean(), requiresAction: z.boolean().optional(),
  clientSecret: z.string().optional(), paymentIntentId: z.string().optional(),
  transactionId: z.string(), transactionStatus: z.string().optional(),
});
export const ConfirmPaymentResponseSchema = z.object({ data: PaymentIntentResultSchema });

export const ApplyCouponRequestSchema = z.object({
  data: z.object({ couponId: z.string(), userId: z.string(), awaitResolved: z.boolean().optional() }),
});
export const CouponSchema = z.object({
  id: z.string(), percent_off: z.number().nullable().optional(),
  amount_off: z.number().nullable().optional(), valid: z.boolean().nullable().optional(),
  name: z.string().nullable().optional(), description: z.string().nullable().optional(),
});
export const ApplyCouponResponseSchema = z.object({
  data: z.object({
    coupon: CouponSchema.nullable().optional(),
    amountAdded: z.number().optional(),
    transactionId: z.string().optional(), transactionStatus: z.string().optional(),
    error: z.object({ message: z.string(), code: z.string().optional(), type: z.string().optional() }).optional(),
  }),
});

export const CustomerTransactionsQuerySchema = z.object({
  limit: z.number().optional(), startingAfter: z.string().optional(),
  endingBefore: z.string().optional(), startDate: z.string().optional(), endDate: z.string().optional(),
});
const StripeTransactionSchema = z.object({
  id: z.string(), amount: z.number(), currency: z.string(), status: z.string(),
  created: z.number(), receiptUrl: z.string().nullable().optional(),
  description: z.string().nullable().optional(),
});
export const CustomerTransactionsResponseSchema = z.object({
  data: z.object({ transactions: z.array(StripeTransactionSchema), hasMore: z.boolean(), nextPage: z.string().nullable().optional() }),
});
export const StripePricesResponseSchema = z.object({
  data: z.array(z.object({ id: z.string(), unitAmount: z.number(), currency: z.string(), description: z.string().nullable().optional() })),
});

export const ValidatePaymentMethodRequestSchema = z.object({ data: z.object({ paymentMethodId: z.string(), paymentIntentId: z.string() }) });
export const ValidatePaymentMethodResponseSchema = z.object({ success: z.boolean() });
export const RemovePaymentMethodParamsSchema = z.object({ paymentMethodId: z.string() });
export const UpdateCustomerOrganizationRequestSchema = z.object({ organization: z.string() });

export const GetBalancesQuerySchema = z.object({ address: z.string().optional() });
export const GetBalancesResponseOutputSchema = z.object({
  data: z.object({ balance: z.number(), deployments: z.number(), total: z.number() }),
});

export const SignTxRequestInputSchema = z.object({
  data: z.object({
    userId: z.string(),
    messages: z.array(z.object({ typeUrl: z.string(), value: z.string() })),
  }),
});
export const SignTxResponseOutputSchema = z.object({
  data: z.object({ code: z.number(), transactionHash: z.string(), rawLog: z.string() }),
});

export const GetUsageHistoryQuerySchema = z.object({
  address: z.string(), startDate: z.string().optional(), endDate: z.string().optional(),
});
export const UsageHistoryResponseSchema = z.array(z.object({
  date: z.string(), activeDeployments: z.number(),
  dailyAktSpent: z.number(), totalAktSpent: z.number(),
  dailyUsdcSpent: z.number(), totalUsdcSpent: z.number(),
  dailyActSpent: z.number(), totalActSpent: z.number(),
  dailyUsdSpent: z.number(), totalUsdSpent: z.number(),
}));
export const UsageHistoryStatsResponseSchema = z.object({
  totalSpent: z.number(), averageSpentPerDay: z.number(),
  totalDeployments: z.number(), averageDeploymentsPerDay: z.number(),
});

// ═══════════════════════════════════════════════════════════════════════════
// USER (extracted from console/apps/api/src/user/)
// ═══════════════════════════════════════════════════════════════════════════

export const UserSchema = z.object({
  id: z.string(), userId: z.string(), username: z.string(),
  email: z.string(), emailVerified: z.boolean(),
  stripeCustomerId: z.string().optional().nullable(),
  bio: z.string().optional().nullable(), subscribedToNewsletter: z.boolean(),
  youtubeUsername: z.string().optional().nullable(),
  twitterUsername: z.string().optional().nullable(),
  githubUsername: z.string().optional().nullable(),
});
export const GetUserResponseOutputSchema = z.object({ data: UserSchema });
export const CheckUsernameParamsSchema = z.object({ username: z.string() });
export const CheckUsernameResponseSchema = z.object({ available: z.boolean() });
export const UpdateUserSettingsRequestSchema = z.object({
  username: z.string().optional(), bio: z.string().optional(),
  youtubeUsername: z.string().optional(), twitterUsername: z.string().optional(),
  githubUsername: z.string().optional(), subscribedToNewsletter: z.boolean().optional(),
});
export const VerifyEmailRequestSchema = z.object({ data: z.object({ email: z.string() }) });

// ═══════════════════════════════════════════════════════════════════════════
// DASHBOARD / ANALYTICS (extracted from console/apps/api/src/dashboard/)
// ═══════════════════════════════════════════════════════════════════════════

const DashboardPeriodSchema = z.object({
  date: z.string(), height: z.number(),
  activeLeaseCount: z.number(), totalLeaseCount: z.number(), dailyLeaseCount: z.number(),
  totalUAktSpent: z.number(), dailyUAktSpent: z.number(),
  totalUActSpent: z.number(), dailyUActSpent: z.number(),
  totalUUsdcSpent: z.number(), dailyUUsdcSpent: z.number(),
  totalUUsdSpent: z.number(), dailyUUsdSpent: z.number(),
  activeCPU: z.number(), activeGPU: z.number(), activeMemory: z.number(), activeStorage: z.number(),
});

export const DashboardDataResponseSchema = z.object({
  chainStats: z.object({
    height: z.number(), transactionCount: z.number(), bondedTokens: z.number(),
    totalSupply: z.number(), communityPool: z.number(), inflation: z.number(),
    stakingAPR: z.number().optional(),
  }),
  now: DashboardPeriodSchema, compare: DashboardPeriodSchema,
  networkCapacity: z.object({
    activeProviderCount: z.number(),
    activeCPU: z.number(), activeGPU: z.number(), activeMemory: z.number(), activeStorage: z.number(),
    pendingCPU: z.number(), pendingGPU: z.number(), pendingMemory: z.number(), pendingStorage: z.number(),
    availableCPU: z.number(), availableGPU: z.number(), availableMemory: z.number(), availableStorage: z.number(),
    totalCPU: z.number(), totalGPU: z.number(), totalMemory: z.number(), totalStorage: z.number(),
  }),
  networkCapacityStats: z.object({
    currentValue: z.number(), compareValue: z.number(),
    snapshots: z.array(z.object({ date: z.string(), value: z.number() })),
    now: z.object({ count: z.number(), cpu: z.number(), gpu: z.number(), memory: z.number(), storage: z.number() }),
    compare: z.object({ count: z.number(), cpu: z.number(), gpu: z.number(), memory: z.number(), storage: z.number() }),
  }),
  latestBlocks: z.array(z.object({
    height: z.number(), transactionCount: z.number(), totalTransactionCount: z.number(), datetime: z.string(),
    proposer: z.object({ address: z.string(), operatorAddress: z.string(), moniker: z.string().nullable(), avatarUrl: z.string().nullable() }),
  })),
  latestTransactions: z.array(z.object({
    height: z.number(), datetime: z.string(), hash: z.string(), isSuccess: z.boolean(),
    error: z.string().nullable(), gasUsed: z.number(), gasWanted: z.number(), fee: z.number(), memo: z.string(),
    messages: z.array(z.object({ id: z.string(), type: z.string(), amount: z.number() })),
  })),
});

export const GraphDataParamsSchema = z.object({ dataName: z.string() });
export const GraphDataResponseSchema = z.object({
  currentValue: z.number(), compareValue: z.number(),
  snapshots: z.array(z.object({ date: z.string(), value: z.number() })),
});

const StatItemSchema = z.object({ active: z.number(), pending: z.number(), available: z.number(), total: z.number() });
export const NetworkCapacityResponseSchema = z.object({
  activeProviderCount: z.number(),
  resources: z.object({
    cpu: StatItemSchema, gpu: StatItemSchema, memory: StatItemSchema,
    storage: z.object({ ephemeral: StatItemSchema, persistent: StatItemSchema, total: StatItemSchema }),
  }),
});

export const MarketDataParamsSchema = z.object({ coin: z.string().optional() });
export const MarketDataResponseSchema = z.object({
  price: z.number(), volume: z.number(), marketCap: z.number(), marketCapRank: z.number(),
  priceChange24h: z.number(), priceChangePercentage24: z.number(),
});

const BmePeriodSchema = z.object({
  date: z.string(), outstandingAct: z.number(), vaultAkt: z.number(), collateralRatio: z.number(),
  dailyAktBurnedForAct: z.number(), totalAktBurnedForAct: z.number(),
  dailyActMinted: z.number(), totalActMinted: z.number(),
  dailyActBurnedForAkt: z.number(), totalActBurnedForAkt: z.number(),
  dailyAktReminted: z.number(), totalAktReminted: z.number(),
  dailyNetAktBurned: z.number(), netAktBurned: z.number(),
});
export const BmeDashboardDataResponseSchema = z.object({ now: BmePeriodSchema, compare: BmePeriodSchema });

export const BmeStatusHistoryResponseSchema = z.array(z.object({
  height: z.number(), date: z.string(), previousStatus: z.string(),
  newStatus: z.string(), collateralRatio: z.number(),
}));

export const LeasesDurationParamsSchema = z.object({ owner: z.string() });
export const LeasesDurationQuerySchema = z.object({
  dseq: z.string().optional(), startDate: z.string().optional(), endDate: z.string().optional(),
});
export const LeasesDurationResponseSchema = z.object({
  leaseCount: z.number(), totalDurationInSeconds: z.number(), totalDurationInHours: z.number(),
  leases: z.array(z.object({
    dseq: z.string(), oseq: z.number(), gseq: z.number(), provider: z.string(),
    startHeight: z.number(), startDate: z.string(), closedHeight: z.number(), closedDate: z.string(),
    durationInBlocks: z.number(), durationInSeconds: z.number(), durationInHours: z.number(),
  })),
});

// ═══════════════════════════════════════════════════════════════════════════
// GPU (extracted from console/apps/api/src/gpu/)
// ═══════════════════════════════════════════════════════════════════════════

export const ListGpuQuerySchema = z.object({
  provider: z.string().optional(), vendor: z.string().optional(),
  model: z.string().optional(), memory_size: z.string().optional(),
});
export const ListGpuResponseSchema = z.object({
  gpus: z.object({
    total: z.object({ allocatable: z.number(), allocated: z.number() }),
    details: z.record(z.string(), z.array(z.object({
      model: z.string(), ram: z.string(), interface: z.string(),
      allocatable: z.number(), allocated: z.number(),
    }))),
  }),
});
export const ListGpuModelsResponseSchema = z.array(z.object({
  name: z.string(), models: z.array(z.object({ name: z.string(), memory: z.array(z.string()), interface: z.array(z.string()) })),
}));
export const GpuBreakdownQuerySchema = z.object({ vendor: z.string().optional(), model: z.string().optional() });
export const GpuBreakdownResponseSchema = z.array(z.object({
  date: z.string(), vendor: z.string(), model: z.string(), providerCount: z.number(),
  nodeCount: z.number(), totalGpus: z.number(), leasedGpus: z.number(), gpuUtilization: z.number(),
}));
export const GpuPricesResponseSchema = z.object({
  availability: z.object({ total: z.number(), available: z.number() }),
  models: z.array(z.object({
    vendor: z.string(), model: z.string(), ram: z.string(), interface: z.string(),
    availability: z.object({ total: z.number(), available: z.number() }),
    providerAvailability: z.object({ total: z.number(), available: z.number() }),
    price: z.object({
      currency: z.string(), min: z.number(), max: z.number(), avg: z.number(),
      weightedAverage: z.number(), med: z.number(),
    }).nullable(),
  })),
});

// ═══════════════════════════════════════════════════════════════════════════
// TEMPLATES (extracted from console/apps/api/src/template/)
// ═══════════════════════════════════════════════════════════════════════════

export const TemplateSchema = z.object({
  id: z.string(), name: z.string(), path: z.string(), logoUrl: z.string().nullable(),
  summary: z.string(), readme: z.string(), deploy: z.string(),
  persistentStorageEnabled: z.boolean(), guide: z.string().optional(),
  githubUrl: z.string(), config: z.object({ ssh: z.boolean().optional() }),
});
export const TemplateSummarySchema = z.object({
  id: z.string(), name: z.string(), logoUrl: z.string().nullable(), summary: z.string(),
  tags: z.array(z.string()).optional(),
});
export const TemplateCategorySchema = z.object({ title: z.string(), templates: z.array(TemplateSummarySchema) });
export const GetTemplatesListResponseSchema = z.object({ data: z.array(TemplateCategorySchema) });
export const GetTemplateByIdParamsSchema = z.object({ id: z.string() });
export const GetTemplateByIdResponseSchema = z.object({ data: TemplateSchema });

// ═══════════════════════════════════════════════════════════════════════════
// TRANSACTIONS — on-chain (extracted from console/apps/api/src/transaction/)
// ═══════════════════════════════════════════════════════════════════════════

export const ListTransactionsQuerySchema = z.object({ limit: z.number().optional() });
export const ListTransactionsResponseSchema = z.array(z.object({
  height: z.number(), datetime: z.string(), hash: z.string(), isSuccess: z.boolean(),
  error: z.string().nullable(), gasUsed: z.number(), gasWanted: z.number(), fee: z.number(), memo: z.string(),
  messages: z.array(z.object({ id: z.string(), type: z.string(), amount: z.number() })),
}));
export const GetTransactionByHashParamsSchema = z.object({ hash: z.string() });
export const GetTransactionByHashResponseSchema = z.object({
  height: z.number(), datetime: z.string(), hash: z.string(), isSuccess: z.boolean(),
  multisigThreshold: z.number().optional(), signers: z.array(z.string()),
  error: z.string().nullable(), gasUsed: z.number(), gasWanted: z.number(), fee: z.number(), memo: z.string(),
  messages: z.array(z.object({ id: z.string(), type: z.string(), data: z.record(z.string()), relatedDeploymentId: z.string().optional().nullable() })),
});

// ═══════════════════════════════════════════════════════════════════════════
// BLOCKS (extracted from console/apps/api/src/block/)
// ═══════════════════════════════════════════════════════════════════════════

export const ListBlocksQuerySchema = z.object({ limit: z.number().optional() });
export const ListBlocksResponseSchema = z.array(z.object({
  height: z.number(), transactionCount: z.number(), totalTransactionCount: z.number(), datetime: z.string(),
  proposer: z.object({ address: z.string(), operatorAddress: z.string(), moniker: z.string(), avatarUrl: z.string().nullable() }),
}));
export const GetBlockByHeightParamsSchema = z.object({ height: z.number() });
export const GetBlockByHeightResponseSchema = z.object({
  height: z.number(), datetime: z.string(), hash: z.string(), gasUsed: z.number(), gasWanted: z.number(),
  proposer: z.object({ operatorAddress: z.string(), moniker: z.string(), avatarUrl: z.string().optional(), address: z.string() }),
  transactions: z.array(z.object({
    hash: z.string(), isSuccess: z.boolean(), error: z.string().optional().nullable(),
    fee: z.number(), datetime: z.string(),
    messages: z.array(z.object({ id: z.string(), type: z.string(), amount: z.number() })),
  })),
});
export const GetPredictedBlockDateParamsSchema = z.object({ height: z.number() });
export const GetPredictedBlockDateResponseSchema = z.object({ predictedDate: z.string(), height: z.number(), blockWindow: z.number() });
export const GetPredictedDateHeightParamsSchema = z.object({ timestamp: z.number() });
export const GetPredictedDateHeightResponseSchema = z.object({ predictedHeight: z.number(), date: z.string(), blockWindow: z.number() });

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATORS (extracted from console/apps/api/src/validator/)
// ═══════════════════════════════════════════════════════════════════════════

export const GetValidatorListResponseSchema = z.array(z.object({
  operatorAddress: z.string(), moniker: z.string(), votingPower: z.number(), commission: z.number(),
  identity: z.string(), votingPowerRatio: z.number(), rank: z.number(), keybaseAvatarUrl: z.string().nullable(),
}));
export const GetValidatorByAddressParamsSchema = z.object({ address: z.string() });
export const GetValidatorByAddressResponseSchema = z.object({
  operatorAddress: z.string(), address: z.string().nullable(), moniker: z.string(),
  keybaseUsername: z.string().nullable(), keybaseAvatarUrl: z.string().nullable(),
  votingPower: z.number(), commission: z.number(), maxCommission: z.number(), maxCommissionChange: z.number(),
  identity: z.string(), description: z.string(), website: z.string(), rank: z.number(),
});

// ═══════════════════════════════════════════════════════════════════════════
// PROPOSALS (extracted from console/apps/api/src/proposal/)
// ═══════════════════════════════════════════════════════════════════════════

export const GetProposalListResponseSchema = z.array(z.object({
  id: z.number(), title: z.string(), status: z.string(),
  submitTime: z.string(), votingStartTime: z.string(), votingEndTime: z.string(), totalDeposit: z.number(),
}));
export const GetProposalByIdParamsSchema = z.object({ id: z.number() });
export const GetProposalByIdResponseSchema = z.object({
  id: z.number(), title: z.string(), description: z.string(), status: z.string(),
  submitTime: z.string(), votingStartTime: z.string(), votingEndTime: z.string(), totalDeposit: z.number(),
  tally: z.object({ yes: z.number(), abstain: z.number(), no: z.number(), noWithVeto: z.number(), total: z.number() }),
  paramChanges: z.array(z.object({ subspace: z.string(), key: z.string(), value: z.string() })),
});

// ═══════════════════════════════════════════════════════════════════════════
// PROVIDER (additional — extracted from console/apps/api/src/provider/)
// ═══════════════════════════════════════════════════════════════════════════

export const AuditorSchema = z.object({ id: z.string(), name: z.string(), address: z.string(), website: z.string() });
export const AuditorListResponseSchema = z.array(AuditorSchema);

export const CreateJwtTokenRequestSchema = z.object({ ttl: z.number(), leases: z.record(z.string(), z.string()) });
export const CreateJwtTokenResponseSchema = z.object({ token: z.string() });

const ProviderPeriodSchema = z.object({
  date: z.string(), height: z.number(), activeLeaseCount: z.number(), totalLeaseCount: z.number(), dailyLeaseCount: z.number(),
  totalUAktEarned: z.number(), dailyUAktEarned: z.number(), totalUUsdcEarned: z.number(), dailyUUsdcEarned: z.number(),
  totalUActEarned: z.number(), dailyUActEarned: z.number(), totalUUsdEarned: z.number(), dailyUUsdEarned: z.number(),
  activeCPU: z.number(), activeGPU: z.number(), activeMemory: z.number(),
  activeEphemeralStorage: z.number(), activePersistentStorage: z.number(), activeStorage: z.number(),
});
export const ProviderDashboardParamsSchema = z.object({ owner: z.string() });
export const ProviderDashboardResponseSchema = z.object({ current: ProviderPeriodSchema, previous: ProviderPeriodSchema });

export const ProviderDeploymentsParamsSchema = z.object({ provider: z.string(), skip: z.number(), limit: z.number() });
export const ProviderDeploymentsQuerySchema = z.object({ status: z.string().optional() });
export const ProviderDeploymentsResponseSchema = z.object({
  total: z.number(),
  deployments: z.array(z.object({
    owner: z.string(), dseq: z.string(), denom: z.string(), createdHeight: z.number(),
    createdDate: z.string().nullable(), status: z.string(), balance: z.number(), transferred: z.number(),
    settledAt: z.number().nullable(),
    resources: z.object({ cpu: z.number(), memory: z.number(), gpu: z.number(), ephemeralStorage: z.number(), persistentStorage: z.number() }),
    leases: z.array(z.object({
      provider: z.string(), gseq: z.number(), oseq: z.number(), price: z.number(),
      createdHeight: z.number(), createdDate: z.string().nullable(),
      closedHeight: z.number().nullable(), closedDate: z.string().nullable(), status: z.string(),
      resources: z.object({ cpu: z.number(), memory: z.number(), gpu: z.number(), ephemeralStorage: z.number(), persistentStorage: z.number() }),
    })),
  })),
});

export const ProviderEarningsParamsSchema = z.object({ owner: z.string() });
export const ProviderEarningsQuerySchema = z.object({ from: z.string(), to: z.string() });
export const ProviderEarningsResponseSchema = z.object({
  earnings: z.object({ totalUAktEarned: z.number(), totalUUsdcEarned: z.number(), totalUActEarned: z.number(), totalUUsdEarned: z.number() }),
});

export const ProviderGraphDataParamsSchema = z.object({ dataName: z.string() });
export const ProviderGraphDataResponseSchema = z.object({
  currentValue: z.number(), compareValue: z.number(),
  snapshots: z.array(z.object({ date: z.string(), value: z.number() })),
  now: z.object({ count: z.number(), cpu: z.number(), gpu: z.number(), memory: z.number(), storage: z.number() }).optional(),
  compare: z.object({ count: z.number(), cpu: z.number(), gpu: z.number(), memory: z.number(), storage: z.number() }).optional(),
});

export const ProviderRegionsResponseSchema = z.array(z.object({
  providers: z.array(z.string()), key: z.string(), description: z.string(), value: z.string().optional(),
}));

export const ProviderVersionsResponseSchema = z.record(z.string(), z.object({
  version: z.string(), count: z.number(), ratio: z.number(), providers: z.array(z.string()),
}));

const ProviderAttributeTypeSchema = z.object({
  key: z.string(), type: z.string(), required: z.boolean(), description: z.string(),
  values: z.array(z.object({ key: z.string(), description: z.string(), value: z.string().nullable() })).nullable().optional(),
});
export const ProviderAttributesSchemaResponseSchema = z.record(z.string(), ProviderAttributeTypeSchema);


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

  // Billing / Wallet / Stripe
  WalletResponseOutputSchema, WalletListResponseOutputSchema, StartTrialRequestInputSchema,
  WalletSettingsSchema, WalletSettingsResponseSchema, CreateWalletSettingsRequestSchema,
  SetupIntentResponseSchema, PaymentMethodSchema, PaymentMethodsResponseSchema,
  PaymentMethodMarkAsDefaultInputSchema, ConfirmPaymentRequestSchema, PaymentIntentResultSchema,
  ConfirmPaymentResponseSchema, ApplyCouponRequestSchema, CouponSchema, ApplyCouponResponseSchema,
  CustomerTransactionsQuerySchema, CustomerTransactionsResponseSchema, StripePricesResponseSchema,
  ValidatePaymentMethodRequestSchema, ValidatePaymentMethodResponseSchema,
  RemovePaymentMethodParamsSchema, UpdateCustomerOrganizationRequestSchema,
  GetBalancesQuerySchema, GetBalancesResponseOutputSchema,
  SignTxRequestInputSchema, SignTxResponseOutputSchema,
  GetUsageHistoryQuerySchema, UsageHistoryResponseSchema, UsageHistoryStatsResponseSchema,
  // User
  UserSchema, GetUserResponseOutputSchema, CheckUsernameParamsSchema, CheckUsernameResponseSchema,
  UpdateUserSettingsRequestSchema, VerifyEmailRequestSchema,
  // Dashboard
  DashboardDataResponseSchema, GraphDataParamsSchema, GraphDataResponseSchema,
  NetworkCapacityResponseSchema, MarketDataParamsSchema, MarketDataResponseSchema,
  BmeDashboardDataResponseSchema, BmeStatusHistoryResponseSchema,
  LeasesDurationParamsSchema, LeasesDurationQuerySchema, LeasesDurationResponseSchema,
  // GPU
  ListGpuQuerySchema, ListGpuResponseSchema, ListGpuModelsResponseSchema,
  GpuBreakdownQuerySchema, GpuBreakdownResponseSchema, GpuPricesResponseSchema,
  // Templates
  TemplateSchema, TemplateSummarySchema, TemplateCategorySchema,
  GetTemplatesListResponseSchema, GetTemplateByIdParamsSchema, GetTemplateByIdResponseSchema,
  // Transactions (on-chain)
  ListTransactionsQuerySchema, ListTransactionsResponseSchema,
  GetTransactionByHashParamsSchema, GetTransactionByHashResponseSchema,
  // Blocks
  ListBlocksQuerySchema, ListBlocksResponseSchema, GetBlockByHeightParamsSchema, GetBlockByHeightResponseSchema,
  GetPredictedBlockDateParamsSchema, GetPredictedBlockDateResponseSchema,
  GetPredictedDateHeightParamsSchema, GetPredictedDateHeightResponseSchema,
  // Validators
  GetValidatorListResponseSchema, GetValidatorByAddressParamsSchema, GetValidatorByAddressResponseSchema,
  // Proposals
  GetProposalListResponseSchema, GetProposalByIdParamsSchema, GetProposalByIdResponseSchema,
  // Provider (additional)
  AuditorSchema, AuditorListResponseSchema, CreateJwtTokenRequestSchema, CreateJwtTokenResponseSchema,
  ProviderDashboardParamsSchema, ProviderDashboardResponseSchema,
  ProviderDeploymentsParamsSchema, ProviderDeploymentsQuerySchema, ProviderDeploymentsResponseSchema,
  ProviderEarningsParamsSchema, ProviderEarningsQuerySchema, ProviderEarningsResponseSchema,
  ProviderGraphDataParamsSchema, ProviderGraphDataResponseSchema,
  ProviderRegionsResponseSchema, ProviderVersionsResponseSchema, ProviderAttributesSchemaResponseSchema,
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
