import { create } from 'zustand'
import type { BackupJob, StorageBackend, Repository, BackupHistory } from '../types'

interface AppState {
  // Jobs
  jobs: BackupJob[]
  setJobs: (jobs: BackupJob[]) => void
  addJob: (job: BackupJob) => void
  updateJob: (id: number, job: Partial<BackupJob>) => void
  removeJob: (id: number) => void

  // Storage Backends
  storageBackends: StorageBackend[]
  setStorageBackends: (backends: StorageBackend[]) => void
  addStorageBackend: (backend: StorageBackend) => void
  removeStorageBackend: (id: number) => void

  // Repositories
  repositories: Repository[]
  setRepositories: (repos: Repository[]) => void
  addRepository: (repo: Repository) => void
  removeRepository: (id: number) => void

  // History
  history: BackupHistory[]
  setHistory: (history: BackupHistory[]) => void

  // UI State
  isLoading: boolean
  setIsLoading: (loading: boolean) => void
  error: string | null
  setError: (error: string | null) => void
}

export const useStore = create<AppState>((set) => ({
  // Jobs
  jobs: [],
  setJobs: (jobs) => set({ jobs }),
  addJob: (job) => set((state) => ({ jobs: [...state.jobs, job] })),
  updateJob: (id, job) => set((state) => ({
    jobs: state.jobs.map((j) => (j.id === id ? { ...j, ...job } : j)),
  })),
  removeJob: (id) => set((state) => ({
    jobs: state.jobs.filter((j) => j.id !== id),
  })),

  // Storage Backends
  storageBackends: [],
  setStorageBackends: (storageBackends) => set({ storageBackends }),
  addStorageBackend: (backend) => set((state) => ({
    storageBackends: [...state.storageBackends, backend],
  })),
  removeStorageBackend: (id) => set((state) => ({
    storageBackends: state.storageBackends.filter((b) => b.id !== id),
  })),

  // Repositories
  repositories: [],
  setRepositories: (repositories) => set({ repositories }),
  addRepository: (repo) => set((state) => ({
    repositories: [...state.repositories, repo],
  })),
  removeRepository: (id) => set((state) => ({
    repositories: state.repositories.filter((r) => r.id !== id),
  })),

  // History
  history: [],
  setHistory: (history) => set({ history }),

  // UI State
  isLoading: false,
  setIsLoading: (isLoading) => set({ isLoading }),
  error: null,
  setError: (error) => set({ error }),
}))
