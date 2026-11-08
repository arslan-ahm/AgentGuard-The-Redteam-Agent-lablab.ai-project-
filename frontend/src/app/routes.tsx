import type { RouteObject } from 'react-router'
import { LoginPage } from '../pages/LoginPage'
import { NotFoundPage } from '../pages/NotFoundPage'
import { DashboardPage } from '../pages/DashboardPage'
import { FindingPage } from '../pages/FindingPage'
import { NewScanPage } from '../pages/NewScanPage'
import { ReportPage } from '../pages/ReportPage'
import { ScanPage } from '../pages/ScanPage'
import { AppLayout } from './AppLayout'
import { RequireAuth } from './RequireAuth'

/** Route map (brief 6.1 / 6.8). Everything except /login requires a signed-in user. */
export const routes: RouteObject[] = [
  { path: '/login', element: <LoginPage /> },
  {
    path: '/',
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'scans/new', element: <NewScanPage /> },
      { path: 'scans/:scanId', element: <ScanPage /> },
      { path: 'scans/:scanId/findings/:findingId', element: <FindingPage /> },
      { path: 'scans/:scanId/report', element: <ReportPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]
