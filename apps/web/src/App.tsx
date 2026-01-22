import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import LoginPage from './pages/auth/login';
import RegisterPage from './pages/auth/register';
import { useAuthStore } from './stores/auth.store';
import DashboardLayout from './layouts/dashboard-layout';
import DashboardPage from './pages/dashboard/dashboard';

// Protected Route Wrapper
const ProtectedRoute = () => {
    const isAuthenticated = useAuthStore((state) => state.isAuthenticated());
    if (!isAuthenticated) return <Navigate to="/login" replace />;
    return <Outlet />;
};

function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />

                {/* Protected Routes */}
                <Route element={<ProtectedRoute />}>
                    <Route element={<DashboardLayout />}>
                        <Route path="/dashboard" element={<DashboardPage />} />
                        {/* Add new routes here */}
                        <Route path="/" element={<Navigate to="/dashboard" replace />} />
                        <Route path="/assets" element={<div className="text-foreground">Assets Manager</div>} />
                    </Route>
                </Route>

                {/* Catch all */}
                <Route path="*" element={<Navigate to="/login" replace />} />
            </Routes>
        </BrowserRouter>
    )
}

export default App
