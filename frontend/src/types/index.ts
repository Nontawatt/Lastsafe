export interface BackupJob {
  id: number
  name: string
  source_path: string
  destination: string
  schedule: string
  enabled: boolean
  last_run: string
  next_run: string
  status: 'idle' | 'running' | 'success' | 'failed'
  created_at: string
  updated_at: string
}

export interface BackupHistory {
  id: number
  job_id: number
  start_time: string
  end_time: string
  status: 'success' | 'failed'
  bytes_added: number
  files_new: number
  files_changed: number
  error_msg: string
  snapshot_id: string
  created_at: string
}

export interface StorageBackend {
  id: number
  name: string
  type: 'local' | 's3' | 'gcs' | 'azure' | 'sftp' | 'b2' | 'gdrive'
  config: string
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface Repository {
  id: number
  name: string
  path: string
  storage_backend_id: number
  initialized: boolean
  created_at: string
  updated_at: string
}

export interface Snapshot {
  id: number
  snapshot_id: string
  repository_id: number
  hostname: string
  paths: string
  time: string
  tags: string
  created_at: string
}

export interface DashboardStats {
  total_jobs: number
  active_jobs: number
  total_backups: number
  successful_backups: number
  failed_backups: number
  total_size: number
  storage_backends: number
}
