import { auth } from "@clerk/nextjs/server";
import Link from "next/link";
import { redirect } from "next/navigation";

const features = [
  {
    number: "01",
    title: "AI-Powered Discovery",
    description:
      "Uncover exposed subdomains, admin panels, development environments, and overlooked assets across your public attack surface.",
  },
  {
    number: "02",
    title: "Professional PDF Reports",
    description:
      "Receive a polished, executive-ready security report that clearly communicates risk to technical and business stakeholders.",
  },
  {
    number: "03",
    title: "Actionable Remediation Steps",
    description:
      "Turn findings into progress with prioritized, practical guidance your team can use to reduce exposure immediately.",
  },
];

const steps = [
  {
    number: "1",
    title: "Enter Domain",
    description: "Tell us which business domain you want to assess.",
  },
  {
    number: "2",
    title: "AI Analyzes",
    description: "Sentinel Scout discovers assets and evaluates their risk.",
  },
  {
    number: "3",
    title: "Download Report",
    description: "Get clear findings and remediation steps in a professional PDF.",
  },
];

export default async function Home() {
  const { userId } = await auth();

  if (userId) {
    redirect("/scan");
  }

  return (
    <div className="min-h-screen bg-white text-zinc-950">
      <header className="border-b border-zinc-200/80">
        <nav className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5 sm:px-8">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-950 text-sm font-bold text-white">
              S
            </span>
            <span className="font-semibold tracking-tight">Sentinel Scout</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link
              href="/sign-in"
              className="px-3 py-2 text-sm font-medium text-zinc-600 transition hover:text-zinc-950"
            >
              Sign In
            </Link>
            <Link
              href="/sign-up"
              className="rounded-lg bg-zinc-950 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-zinc-800"
            >
              Get Started
            </Link>
          </div>
        </nav>
      </header>

      <main>
        <section className="relative overflow-hidden border-b border-zinc-200 bg-zinc-50">
          <div
            className="absolute inset-0 opacity-40"
            style={{
              backgroundImage:
                "radial-gradient(circle at 1px 1px, #d4d4d8 1px, transparent 0)",
              backgroundSize: "28px 28px",
            }}
          />
          <div className="relative mx-auto max-w-6xl px-5 py-24 text-center sm:px-8 sm:py-32">
            <div className="mx-auto inline-flex items-center gap-2 rounded-full border border-zinc-200 bg-white px-3 py-1.5 text-xs font-medium text-zinc-600 shadow-sm">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Built for small businesses
            </div>
            <h1 className="mx-auto mt-7 max-w-4xl text-5xl font-semibold tracking-[-0.04em] text-zinc-950 sm:text-6xl lg:text-7xl">
              See What Hackers See
              <span className="block text-zinc-500">About Your Business</span>
            </h1>
            <p className="mx-auto mt-7 max-w-2xl text-lg leading-8 text-zinc-600">
              AI-powered security reconnaissance that reveals your exposed
              digital assets, explains the risk, and tells you what to fix
              first.
            </p>
            <div className="mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Link
                href="/sign-up"
                className="w-full rounded-lg bg-zinc-950 px-6 py-3.5 text-sm font-semibold text-white shadow-sm transition hover:bg-zinc-800 sm:w-auto"
              >
                Start Your Security Scan
              </Link>
              <a
                href="#how-it-works"
                className="w-full rounded-lg border border-zinc-300 bg-white px-6 py-3.5 text-sm font-semibold text-zinc-800 transition hover:bg-zinc-100 sm:w-auto"
              >
                See How It Works
              </a>
            </div>

            <div className="mt-12 flex flex-wrap items-center justify-center gap-x-8 gap-y-3 text-sm text-zinc-500">
              {["Secure", "Fast", "AI-Powered"].map((badge) => (
                <div key={badge} className="flex items-center gap-2">
                  <svg
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    className="h-4 w-4 text-emerald-600"
                    aria-hidden="true"
                  >
                    <path
                      fillRule="evenodd"
                      d="M16.704 5.29a1 1 0 0 1 .006 1.414l-8 8a1 1 0 0 1-1.414 0l-4-4A1 1 0 0 1 4.71 9.29L8 12.586l7.296-7.296a1 1 0 0 1 1.408 0Z"
                      clipRule="evenodd"
                    />
                  </svg>
                  {badge}
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-5 py-24 sm:px-8">
          <div className="max-w-2xl">
            <p className="text-sm font-semibold uppercase tracking-[0.16em] text-zinc-500">
              Complete visibility
            </p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950 sm:text-4xl">
              Everything you need to understand your exposure
            </h2>
          </div>
          <div className="mt-12 grid gap-px overflow-hidden rounded-2xl border border-zinc-200 bg-zinc-200 md:grid-cols-3">
            {features.map((feature) => (
              <article key={feature.title} className="bg-white p-7 sm:p-8">
                <span className="font-mono text-xs font-semibold text-zinc-400">
                  {feature.number}
                </span>
                <h3 className="mt-8 text-lg font-semibold text-zinc-950">
                  {feature.title}
                </h3>
                <p className="mt-3 text-sm leading-6 text-zinc-600">
                  {feature.description}
                </p>
              </article>
            ))}
          </div>
        </section>

        <section
          id="how-it-works"
          className="border-y border-zinc-200 bg-zinc-50"
        >
          <div className="mx-auto max-w-6xl px-5 py-24 sm:px-8">
            <div className="text-center">
              <p className="text-sm font-semibold uppercase tracking-[0.16em] text-zinc-500">
                How it works
              </p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950 sm:text-4xl">
                From domain to direction in three steps
              </h2>
            </div>
            <div className="relative mt-14 grid gap-8 md:grid-cols-3">
              <div className="absolute top-6 right-[17%] left-[17%] hidden h-px bg-zinc-300 md:block" />
              {steps.map((step) => (
                <article
                  key={step.title}
                  className="relative flex flex-col items-center text-center"
                >
                  <span className="relative z-10 flex h-12 w-12 items-center justify-center rounded-full border border-zinc-300 bg-white text-sm font-semibold text-zinc-950 shadow-sm">
                    {step.number}
                  </span>
                  <h3 className="mt-5 text-base font-semibold text-zinc-950">
                    {step.title}
                  </h3>
                  <p className="mt-2 max-w-xs text-sm leading-6 text-zinc-600">
                    {step.description}
                  </p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-5 py-24 sm:px-8">
          <div className="mx-auto max-w-3xl overflow-hidden rounded-3xl bg-zinc-950 px-6 py-12 text-center text-white shadow-xl sm:px-12 sm:py-16">
            <p className="text-sm font-semibold uppercase tracking-[0.16em] text-zinc-400">
              Simple, one-time pricing
            </p>
            <div className="mt-5 flex items-end justify-center gap-2">
              <span className="text-5xl font-semibold tracking-tight">$299</span>
              <span className="pb-1 text-sm text-zinc-400">
                per comprehensive scan
              </span>
            </div>
            <p className="mx-auto mt-5 max-w-lg text-sm leading-6 text-zinc-300">
              One complete external security assessment, AI-analyzed findings,
              prioritized remediation guidance, and a professional PDF report.
            </p>
            <Link
              href="/sign-up"
              className="mt-8 inline-flex rounded-lg bg-white px-6 py-3.5 text-sm font-semibold text-zinc-950 transition hover:bg-zinc-200"
            >
              Get Started
            </Link>
          </div>
        </section>
      </main>

      <footer className="border-t border-zinc-200">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-5 py-7 text-sm text-zinc-500 sm:flex-row sm:px-8">
          <span className="font-medium text-zinc-700">Sentinel Scout</span>
          <span>AI-powered security reconnaissance for small businesses.</span>
        </div>
      </footer>
    </div>
  );
}
