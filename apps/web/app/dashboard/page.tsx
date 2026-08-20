import { OrganizationSwitcher, UserButton } from "@clerk/nextjs";
import { auth } from "@clerk/nextjs/server";
import { redirect } from "next/navigation";
import { fetchMe, fetchOrganizations } from "@/lib/api";
import { AlertsPanel } from "./alerts-panel";
import { AuditPanel } from "./audit-panel";
import { FindingsPanel } from "./findings-panel";
import { MonitoringPanel } from "./monitoring-panel";
import { OperationsPanel } from "./operations-panel";
import { TargetsPanel } from "./targets-panel";

export default async function DashboardPage() {
  const session = await auth();
  if (!session.userId) {
    redirect("/sign-in");
  }

  const token = await session.getToken();
  if (!token) {
    redirect("/sign-in");
  }

  let meError: string | null = null;
  let me = null;
  let organizations: Awaited<ReturnType<typeof fetchOrganizations>> = [];

  try {
    me = await fetchMe(token);
    organizations = await fetchOrganizations(token);
  } catch (error) {
    meError = error instanceof Error ? error.message : "Failed to load dashboard data";
  }

  const activeOrg =
    organizations.find((org) => org.id === me?.active_organization_id) ?? null;

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-8 px-6 py-10">
      <header className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium tracking-wide text-zinc-500">
            Sentinel Scout
          </p>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        </div>
        <div className="flex items-center gap-3">
          <OrganizationSwitcher hidePersonal />
          <UserButton />
        </div>
      </header>

      {meError ? (
        <section className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          Could not load data from the API. Confirm the API is running and Clerk
          keys match. {meError}
        </section>
      ) : (
        <>
          <section className="space-y-2">
            <h2 className="text-lg font-medium">Signed-in user</h2>
            <dl className="grid gap-2 text-sm text-zinc-700">
              <div>
                <dt className="text-zinc-500">Name</dt>
                <dd>{me?.name ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-zinc-500">Email</dt>
                <dd>{me?.email}</dd>
              </div>
              <div>
                <dt className="text-zinc-500">Clerk user id</dt>
                <dd className="font-mono text-xs">{me?.clerk_user_id}</dd>
              </div>
            </dl>
          </section>

          <section className="space-y-2">
            <h2 className="text-lg font-medium">Active organization</h2>
            {activeOrg ? (
              <dl className="grid gap-2 text-sm text-zinc-700">
                <div>
                  <dt className="text-zinc-500">Name</dt>
                  <dd>{activeOrg.name}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Role</dt>
                  <dd className="font-mono text-xs">{activeOrg.role}</dd>
                </div>
              </dl>
            ) : (
              <p className="text-sm text-zinc-600">
                No active organization in the verified session. Use the
                organization switcher to select one.
              </p>
            )}
          </section>

          <TargetsPanel enabled={Boolean(activeOrg)} />
          <MonitoringPanel enabled={Boolean(activeOrg)} />
          <AlertsPanel enabled={Boolean(activeOrg)} />
          <OperationsPanel enabled={Boolean(activeOrg)} />
          <FindingsPanel enabled={Boolean(activeOrg)} />
          <AuditPanel enabled={Boolean(activeOrg)} />
        </>
      )}
    </div>
  );
}
