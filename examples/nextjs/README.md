# Next.js integration

The dashboard's `/login` and `/dashboard` routes are the maintained Next.js cookie-session example. Browser requests use `credentials: "include"`; no long-lived credential is written to localStorage. Copy those route patterns into an integrating application and register its exact callback/origin in an AuthForge environment.

