import axios from 'axios'
import type { BackupJob, BackupHistory, StorageBackend, Repository, Snapshot } from '../types'

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Health check
export const healthCheck = () => api.get('/health')

// Backup Jobs
export const getJobs = () => api.get<BackupJob[]>('/jobs')
export const getJob = (id: number) => api.get<BackupJob>(`/jobs/${id}`)
export const createJob = (job: Partial<BackupJob>) => api.post<BackupJob>('/jobs', job)
export const updateJob = (id: number, job: Partial<BackupJob>) => api.put<BackupJob>(`/jobs/${id}`, job)
export const deleteJob = (id: number) => api.delete(`/jobs/${id}`)
export const runJob = (id: number) => api.post(`/jobs/${id}/run`)

// Repositories
export const getRepositories = () => api.get<Repository[]>('/repositories')
export const getRepository = (id: number) => api.get<Repository>(`/repositories/${id}`)
export const createRepository = (repo: Partial<Repository>) => api.post<Repository>('/repositories', repo)
export const deleteRepository = (id: number) => api.delete(`/repositories/${id}`)
export const initRepository = (id: number) => api.post(`/repositories/${id}/init`)

// Snapshots
export const getSnapshots = () => api.get<Snapshot[]>('/snapshots')
export const getSnapshot = (id: number) => api.get<Snapshot>(`/snapshots/${id}`)
export const deleteSnapshot = (id: number) => api.delete(`/snapshots/${id}`)
export const restoreSnapshot = (id: number, targetPath: string) =>
  api.post(`/snapshots/${id}/restore`, { target_path: targetPath })

// Storage Backends
export const getStorageBackends = () => api.get<StorageBackend[]>('/storage')
export const getStorageBackend = (id: number) => api.get<StorageBackend>(`/storage/${id}`)
export const createStorageBackend = (backend: Partial<StorageBackend>) =>
  api.post<StorageBackend>('/storage', backend)
export const updateStorageBackend = (id: number, backend: Partial<StorageBackend>) =>
  api.put<StorageBackend>(`/storage/${id}`, backend)
export const deleteStorageBackend = (id: number) => api.delete(`/storage/${id}`)

// History
export const getBackupHistory = () => api.get<BackupHistory[]>('/history')

export default api
