import { Outlet, NavLink } from 'react-router-dom'
import {
  HomeIcon,
  ClockIcon,
  FolderIcon,
  ServerIcon,
  Cog6ToothIcon,
  CircleStackIcon,
} from '@heroicons/react/24/outline'

const navigation = [
  { name: 'Dashboard', href: '/', icon: HomeIcon },
  { name: 'Backup Jobs', href: '/jobs', icon: ClockIcon },
  { name: 'Repositories', href: '/repositories', icon: CircleStackIcon },
  { name: 'Storage Backends', href: '/storage', icon: ServerIcon },
  { name: 'History', href: '/history', icon: FolderIcon },
  { name: 'Settings', href: '/settings', icon: Cog6ToothIcon },
]

function Layout() {
  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 text-white">
        <div className="p-4">
          <h1 className="text-2xl font-bold text-primary-400">Lastsafe</h1>
          <p className="text-sm text-gray-400">Backup & Sync Manager</p>
        </div>
        <nav className="mt-4">
          {navigation.map((item) => (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive }) =>
                `flex items-center px-4 py-3 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-gray-800 text-primary-400 border-l-4 border-primary-400'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`
              }
            >
              <item.icon className="w-5 h-5 mr-3" />
              {item.name}
            </NavLink>
          ))}
        </nav>
      </aside>

      {/* Main content */}
      <main className="flex-1 bg-gray-50">
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

export default Layout
