# Web fonts

Self-hosted copies (latin subset, woff2) of fonts from Google Fonts, all under the SIL Open Font License 1.1:

- Barlow Condensed: https://fonts.google.com/specimen/Barlow+Condensed
- IBM Plex Sans and IBM Plex Mono: https://github.com/IBM/plex
- Inter: https://github.com/rsms/inter
- JetBrains Mono: https://github.com/JetBrains/JetBrainsMono

`make website` copies them to `_site/fonts/`, where the themes in `styles/themes/` load them with `@font-face`.
