import { useState, useCallback } from 'react'
import { useStore } from '../store/useStore'

interface UseApiOptions<T> {
  onSuccess?: (data: T) => void
  onError?: (error: Error) => void
}

export function useApi<T, Args extends unknown[]>(
  apiFunction: (...args: Args) => Promise<{ data: T }>,
  options: UseApiOptions<T> = {}
) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const setGlobalError = useStore((state) => state.setError)

  const execute = useCallback(
    async (...args: Args) => {
      setLoading(true)
      setError(null)
      setGlobalError(null)

      try {
        const response = await apiFunction(...args)
        setData(response.data)
        options.onSuccess?.(response.data)
        return response.data
      } catch (err) {
        const error = err instanceof Error ? err : new Error('An error occurred')
        setError(error)
        setGlobalError(error.message)
        options.onError?.(error)
        throw error
      } finally {
        setLoading(false)
      }
    },
    [apiFunction, options, setGlobalError]
  )

  return { data, loading, error, execute }
}

export function useJobs() {
  const { jobs, setJobs } = useStore()
  const [loading, setLoading] = useState(false)

  const fetchJobs = useCallback(async () => {
    setLoading(true)
    try {
      const { getJobs } = await import('../services/api')
      const response = await getJobs()
      setJobs(response.data)
    } finally {
      setLoading(false)
    }
  }, [setJobs])

  return { jobs, loading, fetchJobs }
}

export function useStorageBackends() {
  const { storageBackends, setStorageBackends } = useStore()
  const [loading, setLoading] = useState(false)

  const fetchStorageBackends = useCallback(async () => {
    setLoading(true)
    try {
      const { getStorageBackends } = await import('../services/api')
      const response = await getStorageBackends()
      setStorageBackends(response.data)
    } finally {
      setLoading(false)
    }
  }, [setStorageBackends])

  return { storageBackends, loading, fetchStorageBackends }
}

export function useRepositories() {
  const { repositories, setRepositories } = useStore()
  const [loading, setLoading] = useState(false)

  const fetchRepositories = useCallback(async () => {
    setLoading(true)
    try {
      const { getRepositories } = await import('../services/api')
      const response = await getRepositories()
      setRepositories(response.data)
    } finally {
      setLoading(false)
    }
  }, [setRepositories])

  return { repositories, loading, fetchRepositories }
}

export function useHistory() {
  const { history, setHistory } = useStore()
  const [loading, setLoading] = useState(false)

  const fetchHistory = useCallback(async () => {
    setLoading(true)
    try {
      const { getBackupHistory } = await import('../services/api')
      const response = await getBackupHistory()
      setHistory(response.data)
    } finally {
      setLoading(false)
    }
  }, [setHistory])

  return { history, loading, fetchHistory }
}
