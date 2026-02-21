
import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/Sidebar';

export function DashboardLayout() {
    return (
        <div className="flex h-screen overflow-hidden bg-[#020617] text-gray-100 font-sans">
            <Sidebar />
            <div className="flex flex-1 flex-col overflow-hidden">
                <main className="flex-1 overflow-y-auto p-6 focus:outline-none">
                    <Outlet />
                </main>
            </div>
        </div>
    );
}
