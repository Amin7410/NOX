import { useState } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
    LayoutDashboard,
    Box,
    GitGraph,
    Settings,
    LogOut,
    ChevronLeft,
    ChevronRight,
    Briefcase
} from 'lucide-react';
import { useAuthStore } from '@/stores/auth.store';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { OrganizationSwitcher } from '@/components/org-switcher';

interface SidebarItemProps {
    icon: React.ElementType;
    label: string;
    href: string;
    isActive: boolean;
    isCollapsed: boolean;
}

const SidebarItem = ({ icon: Icon, label, href, isActive, isCollapsed }: SidebarItemProps) => {
    return (
        <Link
            to={href}
            className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-md transition-colors duration-200 group relative",
                isActive
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-white/5 hover:text-white"
            )}
        >
            <Icon size={20} />
            {!isCollapsed && (
                <span className="text-sm font-medium whitespace-nowrap overflow-hidden transition-all duration-300">
                    {label}
                </span>
            )}
            {isCollapsed && (
                <div className="absolute left-[120%] z-50 rounded-md bg-popover px-2 py-1 text-xs text-popover-foreground shadow-md opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity">
                    {label}
                </div>
            )}
        </Link>
    );
};

export default function DashboardLayout() {
    const [isCollapsed, setIsCollapsed] = useState(false);
    const location = useLocation();
    const { logout, user } = useAuthStore();

    const sidebarItems = [
        { icon: LayoutDashboard, label: 'Overview', href: '/dashboard' },
        { icon: Briefcase, label: 'Projects', href: '/projects' },
        { icon: Box, label: 'Assets', href: '/assets' },
        { icon: GitGraph, label: 'Graph View', href: '/graph' }, // Future
        { icon: Settings, label: 'Settings', href: '/settings' },
    ];

    return (
        <div className="flex h-screen bg-background text-foreground overflow-hidden">
            {/* Sidebar */}
            <motion.aside
                initial={false}
                animate={{ width: isCollapsed ? 70 : 250 }}
                className="h-full border-r border-border bg-card/50 backdrop-blur-sm flex flex-col relative"
            >
                {/* Logo Area */}
                <div className="h-14 flex items-center justify-center border-b border-border/50">
                    {isCollapsed ? (
                        <span className="font-bold text-xl text-primary">N</span>
                    ) : (
                        <span className="font-bold text-xl tracking-tight">NOX</span>
                    )}
                </div>

                <div className="p-2 border-b border-border/50">
                    <OrganizationSwitcher isCollapsed={isCollapsed} />
                </div>

                {/* Toggle Button */}
                <button
                    onClick={() => setIsCollapsed(!isCollapsed)}
                    className="absolute -right-3 top-16 bg-card border border-border rounded-full p-1 text-muted-foreground hover:text-foreground transition-colors z-20"
                >
                    {isCollapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
                </button>

                {/* Navigation */}
                <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
                    {sidebarItems.map((item) => (
                        <SidebarItem
                            key={item.href}
                            {...item}
                            isActive={location.pathname === item.href}
                            isCollapsed={isCollapsed}
                        />
                    ))}
                </nav>

                {/* User Footer */}
                <div className="p-3 border-t border-border/50">
                    <div className={cn("flex items-center gap-3", isCollapsed ? "justify-center" : "px-1")}>
                        <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center text-xs font-medium text-primary uppercase">
                            {user?.fullName?.[0] || 'U'}
                        </div>
                        {!isCollapsed && (
                            <div className="flex-1 overflow-hidden">
                                <p className="text-sm font-medium truncate">{user?.fullName}</p>
                                <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                            </div>
                        )}
                        {!isCollapsed && (
                            <Button variant="ghost" size="icon" className="h-8 w-8 text-muted-foreground hover:text-destructive" onClick={logout}>
                                <LogOut size={16} />
                            </Button>
                        )}
                    </div>
                </div>
            </motion.aside>

            {/* Main Content */}
            <main className="flex-1 flex flex-col min-w-0 bg-background/50">
                {/* Header (Optional, for Breadcrumbs or Actions) */}
                <header className="h-14 border-b border-border/50 flex items-center px-6 justify-between bg-background/50 backdrop-blur-sm">
                    <div className="text-sm text-muted-foreground">
                        {/* Breadcrumbs Placeholder */}
                        Isolating Complexity &bull; <span className="text-foreground">{location.pathname}</span>
                    </div>
                    <div>
                        {/* Header Actions Placeholder */}
                    </div>
                </header>

                {/* Content Scroll View */}
                <div className="flex-1 overflow-y-auto p-6 scroll-smooth">
                    <Outlet />
                </div>
            </main>
        </div>
    );
}
