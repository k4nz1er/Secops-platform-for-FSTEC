export type WorkStatus = "В работе" | "Выполнена" | "Закрыта";

export type IocType = "IP" | "Domain" | "URL" | "MD5" | "SHA1" | "SHA256";

export type IocStatus = "Активен" | "Заблокирован" | "Ложное срабатывание";

export interface User {
  id: number;
  name: string;
  role: string;
}

export interface Vulnerability {
  id: number;
  bdu: string | null;
  cve: string | null;
  source_document: string | null;
  affected_software: string | null;
  recommendations: string | null;
  description: string;
  action_taken: string;
  status: WorkStatus | string;
  created_at?: string;
}

export interface VulnerabilityUpdatePayload {
  bdu?: string | null;
  cve?: string | null;
  source_document?: string | null;
  affected_software?: string | null;
  recommendations?: string | null;
  description?: string;
  action_taken?: string;
  status?: WorkStatus;
}

export interface KanbanCard {
  task_id: number;
  vulnerability_id: number;
  source_document: string | null;
  bdu: string | null;
  cve: string | null;
  description: string;
  action_taken: string;
  assignee_id: number;
  assignee_name: string;
  deadline: string;
  status: WorkStatus | string;
}

export interface DashboardMetrics {
  total_tasks: number;
  total_vulnerabilities: number;
  total_iocs: number;
  completion_percentage: number;
}

export interface DashboardState {
  metrics: DashboardMetrics;
  columns: {
    in_progress: KanbanCard[];
    closed: KanbanCard[];
  };
}

export interface TaskUpdatePayload {
  status?: WorkStatus;
  action_taken?: string;
  assignee?: number;
}

export interface IocItem {
  id: number;
  type: IocType | string;
  value: string;
  source: string;
  reputation: string;
  status: IocStatus | string;
  created_at: string;
}

export interface IocUpdatePayload {
  status?: IocStatus | string;
  reputation?: string;
}

export interface DocumentUploadResponse {
  status: string;
  task_id: string;
  filename: string;
}

export interface TaskProcessingResult {
  status?: string;
  filename?: string;
  source_document?: string;
  vulnerabilities_created?: number;
  iocs_created?: number;
  bdu_found?: string[];
}

export interface TaskProcessingStatus {
  task_id: string;
  state: "PENDING" | "STARTED" | "SUCCESS" | "FAILURE" | string;
  result: TaskProcessingResult | null;
}

export interface ActionHistoryItem {
  id: number;
  object_type: string;
  object_id: number;
  action: string;
  user: string;
  timestamp: string;
}
