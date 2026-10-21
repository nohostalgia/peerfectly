# Branding

The pictures the published program carries, and where each is used. They are the peerfectly logo:
not licensed under the AGPL, as [`TRADEMARKS.md`](../TRADEMARKS.md) says.

## Where it's used

| What | File | By |
|---|---|---|
| The programs, the Start menu, the list of installed apps | `deploy/windows/peerfectly.ico` | `programs/build.rs`, at build time |
| The tray icon, with its status dot | the 32-pixel image in `peerfectly.ico` | `windows-daemon`, at run time |
| The installer's banner and dialog pictures | `branding/installer/banner.png`, `dialog.png` | `deploy/windows/package.ps1`, at build time |
| The README's banner, dark and light, and the repository's social preview | `.github/assets/` | GitHub: the README picks the banner matching the reader's theme; the preview is uploaded in the repository's settings |

The drawings these are made from are not in this repository. The `.ico` and the pictures are kept
as built, so a build needs nothing else.

## The installer's pictures

Both are drawn at twice the size Windows Installer shows them, which keeps them sharp on a dense
screen. Windows writes over part of each, so those parts stay plain:

- `banner.png`, 986 × 116: a page's title and description sit over the left 800 pixels or so;
  the mark is on the right.
- `dialog.png`, 986 × 624: the text and the checkbox of the first and last pages sit right of the
  dark band, which is 328 pixels wide.
