import { useEffect } from 'react'
import {
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ServerStackIcon,
} from '@heroicons/react/24/outline'
import { useJobs, useStorageBackends, useHistory } from '../hooks/useApi'

function Dashboard() {
  const { jobs, fetchJobs } = useJobs()
  const { storageBackends, fetchStorageBackends } = useStorageBackends()
  const { history, fetchHistory } = useHistory()

  useEffect(() => {
    fetchJobs()
    fetchStorageBackends()
    fetchHistory()
  }, [fetchJobs, fetchStorageBackends, fetchHistory])

  const stats = [
    {
      name: 'Total Jobs',
      value: jobs.length,
      icon: ClockIcon,
      color: 'bg-blue-500',
    },
    {
      name: 'Active Jobs',
      value: jobs.filter((j) => j.enabled).length,
      icon: CheckCircleIcon,
      color: 'bg-green-500',
    },
    {
      name: 'Failed Backups',
      value: history.filter((h) => h.status === 'failed').length,
      icon: XCircleIcon,
      color: 'bg-red-500',
    },
    {
      name: 'Storage Backends',
      value: storageBackends.length,
      icon: ServerStackIcon,
      color: 'bg-purple-500',
    },
  ]

  const recentHistory = history.slice(0, 5)

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Dashboard</h1>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {stats.map((stat) => (
          <div
            key={stat.name}
            className="bg-white rounded-lg shadow p-6 flex items-center"
          >
            <div className={`${stat.color} p-3 rounded-lg mr-4`}>
              <stat.icon className="w-6 h-6 text-white" />
            </div>
            <div>
              <p className="text-sm text-gray-500">{stat.name}</p>
              <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Recent Activity</h2>
        </div>
        <div className="p-6">
          {recentHistory.length === 0 ? (
            <p className="text-gray-500 text-center py-4">No backup history yet</p>
          ) : (
            <div className="space-y-4">
              {recentHistory.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0"
                >
                  <div className="flex items-center">
                    {item.status === 'success' ? (
                      <CheckCircleIcon className="w-5 h-5 text-green-500 mr-3" />
                    ) : (
                      <XCircleIcon className="w-5 h-5 text-red-500 mr-3" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        Job #{item.job_id}
                      </p>
                      <p className="text-xs text-gray-500">
                        {new Date(item.start_time).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        item.status === 'success'
                          ? 'bg-green-100 text-green-800'
                          : 'bg-red-100 text-red-800'
                      }`}
                    >
                      {item.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default Dashboard
