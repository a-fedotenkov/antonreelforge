# How this site gets deployed

Live: https://antonreelforge.com (Vercel, auto-deploy on push to this repo).

The page itself is built on the render machine at
`/opt/factory/repo/output/vitrina-site`. That directory is the source of
truth for content; this repo is the delivery channel.

To publish changes, run on the render machine:

    /opt/factory/deploy_vitrina.sh "what changed"

It copies the built site here, commits, pushes, and then verifies the live URL
actually serves the new version before reporting success.

Added 2026-09-24, after a fixed duplicate video sat undeployed for two days.
