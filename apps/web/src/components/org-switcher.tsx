import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronsUpDown, Check, Plus } from 'lucide-react';
import api from '@/lib/api';
import { useOrgStore } from '@/stores/org.store';
import { cn } from '@/lib/utils';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';

interface Organization {
    id: string;
    name: string;
    slug: string;
}

export function OrganizationSwitcher({ isCollapsed }: { isCollapsed: boolean }) {
    const { currentOrg, setCurrentOrg } = useOrgStore();
    const navigate = useNavigate();

    // Fetch user's organizations
    const { data: orgs, isLoading, error } = useQuery<Organization[]>({
        queryKey: ['organizations'],
        queryFn: async () => {
            const res = await api.get('/orgs');
            return res.data;
        },
        retry: false,
    });

    // Auto-select first org if none selected and orgs exist
    useEffect(() => {
        if (!currentOrg && orgs && orgs.length > 0) {
            setCurrentOrg(orgs[0]);
        }
    }, [orgs, currentOrg, setCurrentOrg]);

    if (isLoading) return <div className="h-12 animate-pulse bg-white/5 rounded-md mx-2 mb-2" />

    // Handle error or empty state
    if (error || !orgs || orgs.length === 0) {
        return (
            <Button
                variant="ghost"
                className={cn(
                    "w-full justify-between mb-2 hover:bg-white/5",
                    isCollapsed ? "px-2" : "px-3"
                )}
                onClick={() => navigate('/onboarding')}
            >
                <div className="flex items-center gap-2 overflow-hidden">
                    <div className="h-6 w-6 rounded bg-indigo-500/20 text-indigo-500 flex items-center justify-center shrink-0 border border-indigo-500/30">
                        <Plus className="h-4 w-4" />
                    </div>
                    {!isCollapsed && (
                        <span className="truncate text-sm font-medium">
                            Create Organization
                        </span>
                    )}
                </div>
            </Button>
        );
    }

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button
                    variant="ghost"
                    className={cn(
                        "w-full justify-between mb-2 hover:bg-white/5",
                        isCollapsed ? "px-2" : "px-3"
                    )}
                >
                    <div className="flex items-center gap-2 overflow-hidden">
                        <div className="h-6 w-6 rounded bg-indigo-500/20 text-indigo-500 flex items-center justify-center shrink-0 border border-indigo-500/30">
                            <span className="text-xs font-bold">
                                {currentOrg ? currentOrg.name[0] : '+'}
                            </span>
                        </div>
                        {!isCollapsed && (
                            <span className="truncate text-sm font-medium">
                                {currentOrg ? currentOrg.name : 'Select Org'}
                            </span>
                        )}
                    </div>
                    {!isCollapsed && <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />}
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="w-[200px] bg-popover border-border p-1" align="start">
                <DropdownMenuLabel className="text-xs text-muted-foreground px-2 py-1.5">
                    Organizations
                </DropdownMenuLabel>
                {orgs?.map((org) => (
                    <DropdownMenuItem
                        key={org.id}
                        onSelect={() => setCurrentOrg(org)}
                        className="flex items-center justify-between cursor-pointer"
                    >
                        <span>{org.name}</span>
                        {currentOrg?.id === org.id && <Check className="h-4 w-4" />}
                    </DropdownMenuItem>
                ))}
                <DropdownMenuSeparator className="bg-border/50" />
                <DropdownMenuItem className="cursor-pointer text-muted-foreground hover:text-foreground">
                    <Plus className="mr-2 h-4 w-4" />
                    Create Organization
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}
