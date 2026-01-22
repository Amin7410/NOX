import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface Organization {
    id: string;
    name: string;
    slug: string;
    role?: string;
}

interface OrgState {
    currentOrg: Organization | null;
    setCurrentOrg: (org: Organization) => void;
    // We might want to clear org when logging out, but persist handles storage
}

export const useOrgStore = create<OrgState>()(
    persist(
        (set) => ({
            currentOrg: null,
            setCurrentOrg: (org) => set({ currentOrg: org }),
        }),
        {
            name: 'nox-org-storage',
        }
    )
);
