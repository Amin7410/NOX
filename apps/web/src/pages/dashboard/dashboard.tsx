import { useAuthStore } from "../../stores/auth.store";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function DashboardPage() {
    const user = useAuthStore((state) => state.user);

    return (
        <div className="p-8 space-y-8">
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
                    <p className="text-muted-foreground">Welcome back, {user?.fullName}</p>
                </div>
                <Button>Create New Project</Button>
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Projects</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">0</div>
                        <p className="text-xs text-muted-foreground">Available projects</p>
                    </CardContent>
                </Card>
            </div>

            <div className="flex flex-col items-center justify-center h-[400px] border border-dashed rounded-lg bg-black/20">
                <p className="text-muted-foreground mb-4">No projects found. This is a clean slate for the new team.</p>
                <Button variant="outline">Start Building Features</Button>
            </div>
        </div>
    );
}
