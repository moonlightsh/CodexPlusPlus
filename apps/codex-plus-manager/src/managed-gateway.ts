/// Windows 受管模型网关的前端状态视图（与后端 ManagedGatewayStatusPayload 对应）。

export interface ManagedGatewayStatus {
  enabled: boolean;
  credentialConfigured: boolean;
  externalCatalogConflict: string | null;
}

export type ManagedGatewayStatusKind = "not-configured" | "ready" | "conflict" | "disabled";

/// 状态归类：
/// - conflict：存在外部 model_catalog_json 指针（初始化完成时会备份并移除指针）
/// - ready：已启用且凭据已配置
/// - disabled：已启用但凭据缺失（或反之：配置了 Key 未启用）
/// - not-configured：均未就绪
export function describeManagedGatewayStatus(
  status: ManagedGatewayStatus,
): ManagedGatewayStatusKind {
  if (status.externalCatalogConflict) return "conflict";
  if (status.enabled && status.credentialConfigured) return "ready";
  if (status.enabled || status.credentialConfigured) return "disabled";
  return "not-configured";
}
