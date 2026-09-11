# Diagram sources

`pipeline.svg` is hand-written and is the source — there is no build step and no
tool to install.

It is animated with CSS (a request travelling the pipeline, each stage lighting
up as it arrives), which GitHub renders when the file is referenced from an
`<img>` tag. Three things it deliberately does:

- **adapts to theme** via `prefers-color-scheme`, so it is legible on GitHub's
  dark background as well as light;
- **stops moving** under `prefers-reduced-motion`, leaving a static diagram;
- **carries `<title>` and `<desc>`**, so a screen reader gets the same
  explanation the picture gives.

No `<script>`: GitHub strips it, and the animation does not need it.

To check a change, render it to a PNG and look:

```bash
rsvg-convert -w 980 pipeline.svg -o /tmp/pipeline.png   # brew install librsvg
```

That renders the first frame only. For the animation, open the file in a
browser.
