export type GenerateTokenCallback<ServiceClass> = (
  data: GenerateTokenCallbackData,
  ctx: ServiceClass,
) => boolean;

export interface GenerateTokenCallbackData {
  ClientID: string;
  ClientSecret: string;
}
