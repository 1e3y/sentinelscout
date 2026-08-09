import Link from "next/link";
import { auth } from "@clerk/nextjs/server";
import { redirect } from "next/navigation";

export default async function HomePage() {
  const { userId } = await auth();
  if (userId) {
    redirect("/dashboard");
  }

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col justify-center gap-6 px-6 py-16">
      <p className="text-sm font-medium tracking-wide text-zinc-500">
        Sentinel Scout
      </p>
      <h1 className="text-4xl font-semibold tracking-tight">Sign in to continue</h1>
      <p className="max-w-xl text-lg text-zinc-600">
        Milestone 1 provides authenticated access and organization context. All
        authorization is enforced by the API.
      </p>
      <div className="flex gap-3">
        <Link
          href="/sign-in"
          className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white"
        >
          Sign in
        </Link>
        <Link
          href="/sign-up"
          className="rounded-md border border-zinc-300 bg-white px-4 py-2 text-sm font-medium text-zinc-900"
        >
          Sign up
        </Link>
      </div>
    </main>
  );
}
