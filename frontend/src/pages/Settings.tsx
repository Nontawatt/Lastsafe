import { useState } from 'react'

function Settings() {
  const [settings, setSettings] = useState({
    resticPath: '/usr/bin/restic',
    rclonePath: '/usr/bin/rclone',
    defaultRetention: '7d',
    notificationsEnabled: true,
    emailNotifications: '',
  })

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault()
    // TODO: Save settings to backend
    alert('Settings saved!')
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Settings</h1>

      <div className="bg-white rounded-lg shadow p-6 max-w-2xl">
        <form onSubmit={handleSave}>
          <div className="space-y-6">
            {/* Paths Section */}
            <div>
              <h2 className="text-lg font-medium text-gray-900 mb-4">Tool Paths</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Restic Path
                  </label>
                  <input
                    type="text"
                    value={settings.resticPath}
                    onChange={(e) => setSettings({ ...settings, resticPath: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Rclone Path
                  </label>
                  <input
                    type="text"
                    value={settings.rclonePath}
                    onChange={(e) => setSettings({ ...settings, rclonePath: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                  />
                </div>
              </div>
            </div>

            {/* Backup Settings */}
            <div>
              <h2 className="text-lg font-medium text-gray-900 mb-4">Backup Settings</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Default Retention Period
                  </label>
                  <select
                    value={settings.defaultRetention}
                    onChange={(e) => setSettings({ ...settings, defaultRetention: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                  >
                    <option value="1d">1 day</option>
                    <option value="7d">7 days</option>
                    <option value="30d">30 days</option>
                    <option value="90d">90 days</option>
                    <option value="365d">1 year</option>
                    <option value="forever">Forever</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Notifications */}
            <div>
              <h2 className="text-lg font-medium text-gray-900 mb-4">Notifications</h2>
              <div className="space-y-4">
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="notifications"
                    checked={settings.notificationsEnabled}
                    onChange={(e) => setSettings({ ...settings, notificationsEnabled: e.target.checked })}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <label htmlFor="notifications" className="ml-2 block text-sm text-gray-700">
                    Enable email notifications
                  </label>
                </div>
                {settings.notificationsEnabled && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Email Address
                    </label>
                    <input
                      type="email"
                      value={settings.emailNotifications}
                      onChange={(e) => setSettings({ ...settings, emailNotifications: e.target.value })}
                      placeholder="admin@example.com"
                      className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
                    />
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="mt-8 flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700"
            >
              Save Settings
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default Settings
