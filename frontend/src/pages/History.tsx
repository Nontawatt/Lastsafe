import { useEffect } from 'react'
import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/outline'
import { useHistory } from '../hooks/useApi'

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function formatDuration(start: string, end: string): string {
  const startTime = new Date(start).getTime()
  const endTime = new Date(end).getTime()
  const duration = Math.floor((endTime - startTime) / 1000)

  if (duration < 60) return `${duration}s`
  if (duration < 3600) return `${Math.floor(duration / 60)}m ${duration % 60}s`
  return `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`
}

function History() {
  const { history, fetchHistory } = useHistory()

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory])

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Backup History</h1>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Job</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Started</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Duration</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Files</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Size Added</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Snapshot</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {history.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-8 text-center text-gray-500">
                  No backup history yet
                </td>
              </tr>
            ) : (
              history.map((item) => (
                <tr key={item.id}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {item.status === 'success' ? (
                      <CheckCircleIcon className="w-6 h-6 text-green-500" />
                    ) : (
                      <XCircleIcon className="w-6 h-6 text-red-500" />
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    Job #{item.job_id}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(item.start_time).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {item.end_time ? formatDuration(item.start_time, item.end_time) : '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {item.files_new > 0 && <span className="text-green-600">+{item.files_new} new</span>}
                    {item.files_new > 0 && item.files_changed > 0 && ', '}
                    {item.files_changed > 0 && <span className="text-yellow-600">{item.files_changed} changed</span>}
                    {item.files_new === 0 && item.files_changed === 0 && '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {item.bytes_added ? formatBytes(item.bytes_added) : '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                    {item.snapshot_id ? item.snapshot_id.substring(0, 8) : '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default History
