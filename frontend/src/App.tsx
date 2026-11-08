// Web app root. Owner: Ayesha (Web app / UI, brief 6.1).
import { createBrowserRouter, RouterProvider } from 'react-router'
import { routes } from './app/routes'
import { AuthProvider } from './auth/AuthProvider'

const router = createBrowserRouter(routes)

export default function App() {
  return (
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  )
}
