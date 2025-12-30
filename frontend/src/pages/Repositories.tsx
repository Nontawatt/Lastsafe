import { useEffect, useState } from 'react'
import { PlusIcon, TrashIcon, CheckCircleIcon } from '@heroicons/react/24/outline'
import { useRepositories, useStorageBackends } from '../hooks/useApi'
import { createRepository, deleteRepository, initRepository } from '../services/api'

function Repositories() {
  const { repositories, fetchRepositories } = useRepositories()
  const { storageBackends, fetchStorageBackends } = useStorageBackends()
  const [showModal, setShowModal] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    path: '',
    storage_backend_id: 0,
  })

  useEffect(() => {
    fetchRepositories()
    fetchStorageBackends()
  }, [fetchRepositories, fetchStorageBackends])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    await createRepository(formData)
    setShowModal(false)
    setFormData({ name: '', path: '', storage_backend_id: 0 })
    fetchRepositories()
  }

  const handleDelete = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this repository?')) {
      await deleteRepository(id)
      fetchRepositories()
    }
  }

  const handleInit = async (id: number) => {
    await initRepository(id)
    fetchRepositories()
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Repositories</h1>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          New Repository
        </button>
      </div>

      {/* Repositories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {repositories.length === 0 ? (
          <div className="col-span-full bg-white rounded-lg shadow p-8 text-center text-gray-500">
            No repositories configured yet
          </div>
        ) : (
          repositories.map((repo) => (
            <div key={repo.id} className="bg-white rounded-lg shadow p-6">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{repo.name}</h3>
                  <p className="text-sm text-gray-500">{repo.path}</p>
                </div>
                <span
                  className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    repo.initialized
                      ? 'bg-green-100 text-green-800'
                      : 'bg-yellow-100 text-yellow-800'
                  }`}
                >
                  {repo.initialized ? 'Initialized' : 'Not Initialized'}
                </span>
              </div>
              <div className="flex justify-end space-x-2">
                {!repo.initialized && (
                  <button
                    onClick={() => handleInit(repo.id)}
                    className="flex items-center px-3 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700"
                  >
                    <CheckCircleIcon className="w-4 h-4 mr-1" />
                    Initialize
                  </button>
                )}
                <button
                  onClick={() => handleDelete(repo.id)}
                  className="flex items-center px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700"
                >
                  <TrashIcon className="w-4 h-4 mr-1" />
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Create Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h2 className="text-lg font-semibold mb-4">Create Repository</h2>
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
                  <label className="block text-sm font-medium text-gray-700">Path</label>
                  <input
                    type="text"
                    value={formData.path}
                    onChange={(e) => setFormData({ ...formData, path: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Storage Backend</label>
                  <select
                    value={formData.storage_backend_id}
                    onChange={(e) => setFormData({ ...formData, storage_backend_id: Number(e.target.value) })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                  >
                    <option value={0}>Local</option>
                    {storageBackends.map((backend) => (
                      <option key={backend.id} value={backend.id}>
                        {backend.name} ({backend.type})
                      </option>
                    ))}
                  </select>
                </div>
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
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default Repositories
