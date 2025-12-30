import { useEffect, useState } from 'react'
import { PlusIcon, TrashIcon, ServerIcon } from '@heroicons/react/24/outline'
import { useStorageBackends } from '../hooks/useApi'
import { createStorageBackend, deleteStorageBackend } from '../services/api'
import type { StorageBackend } from '../types'

const storageTypes = [
  { value: 'local', label: 'Local Filesystem' },
  { value: 's3', label: 'Amazon S3' },
  { value: 'gcs', label: 'Google Cloud Storage' },
  { value: 'azure', label: 'Azure Blob Storage' },
  { value: 'b2', label: 'Backblaze B2' },
  { value: 'sftp', label: 'SFTP' },
  { value: 'gdrive', label: 'Google Drive' },
]

function StorageBackends() {
  const { storageBackends, fetchStorageBackends } = useStorageBackends()
  const [showModal, setShowModal] = useState(false)
  const [formData, setFormData] = useState<{
    name: string
    type: StorageBackend['type']
    config: Record<string, string>
  }>({
    name: '',
    type: 'local',
    config: {},
  })

  useEffect(() => {
    fetchStorageBackends()
  }, [fetchStorageBackends])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    await createStorageBackend({
      name: formData.name,
      type: formData.type,
      config: JSON.stringify(formData.config),
    })
    setShowModal(false)
    setFormData({ name: '', type: 'local', config: {} })
    fetchStorageBackends()
  }

  const handleDelete = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this storage backend?')) {
      await deleteStorageBackend(id)
      fetchStorageBackends()
    }
  }

  const getTypeIcon = (type: string) => {
    return <ServerIcon className="w-8 h-8 text-gray-400" />
  }

  const getConfigFields = (type: string) => {
    switch (type) {
      case 's3':
        return ['access_key_id', 'secret_access_key', 'region', 'bucket']
      case 'gcs':
        return ['project', 'bucket', 'service_account_file']
      case 'azure':
        return ['account', 'key', 'container']
      case 'b2':
        return ['account', 'key', 'bucket']
      case 'sftp':
        return ['host', 'user', 'port', 'key_file']
      case 'gdrive':
        return ['client_id', 'client_secret', 'root_folder_id']
      case 'local':
      default:
        return ['path']
    }
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Storage Backends</h1>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add Storage
        </button>
      </div>

      {/* Storage Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {storageBackends.length === 0 ? (
          <div className="col-span-full bg-white rounded-lg shadow p-8 text-center text-gray-500">
            No storage backends configured yet
          </div>
        ) : (
          storageBackends.map((backend) => (
            <div key={backend.id} className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center mb-4">
                {getTypeIcon(backend.type)}
                <div className="ml-4">
                  <h3 className="text-lg font-semibold text-gray-900">{backend.name}</h3>
                  <p className="text-sm text-gray-500 capitalize">{backend.type}</p>
                </div>
              </div>
              <div className="flex justify-between items-center">
                <span
                  className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    backend.enabled
                      ? 'bg-green-100 text-green-800'
                      : 'bg-gray-100 text-gray-800'
                  }`}
                >
                  {backend.enabled ? 'Enabled' : 'Disabled'}
                </span>
                <button
                  onClick={() => handleDelete(backend.id)}
                  className="text-red-600 hover:text-red-900"
                >
                  <TrashIcon className="w-5 h-5" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Create Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
            <h2 className="text-lg font-semibold mb-4">Add Storage Backend</h2>
            <form onSubmit={handleSubmit}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Name</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Type</label>
                  <select
                    value={formData.type}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        type: e.target.value as StorageBackend['type'],
                        config: {},
                      })
                    }
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                  >
                    {storageTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                </div>
                {getConfigFields(formData.type).map((field) => (
                  <div key={field}>
                    <label className="block text-sm font-medium text-gray-700 capitalize">
                      {field.replace(/_/g, ' ')}
                    </label>
                    <input
                      type={field.includes('key') || field.includes('secret') ? 'password' : 'text'}
                      value={formData.config[field] || ''}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          config: { ...formData.config, [field]: e.target.value },
                        })
                      }
                      className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                    />
                  </div>
                ))}
              </div>
              <div className="mt-6 flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700"
                >
                  Add
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default StorageBackends
