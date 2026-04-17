"""Convert HTML report files to PDF using Playwright (headless Chromium)."""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("enterprisesecurityiq")


async def html_to_pdf(html_path: Path | str) -> Path | None:
    """Render *html_path* in headless Chromium and save a PDF alongside it.

    Returns the PDF path on success, ``None`` on failure (logged as warning).
    """
    html_path = Path(html_path)
    if not html_path.exists():
        log.warning("[PDF] HTML file not found: %s", html_path)
        return None

    pdf_path = html_path.with_suffix(".pdf")

    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1280, "height": 900})
            await page.goto(html_path.as_uri(), wait_until="networkidle")

            # Expand all collapsed <details> elements so nothing is hidden
            await page.evaluate("""() => {
                document.querySelectorAll('details:not([open])').forEach(d => d.open = true);
            }""")
            # Small wait for any CSS transitions after expansion
            await page.wait_for_timeout(300)

            await page.pdf(
                path=str(pdf_path),
                format="A4",
                landscape=True,
                print_background=True,
                margin={"top": "12mm", "right": "10mm", "bottom": "12mm", "left": "10mm"},
            )
            await browser.close()

        size_kb = pdf_path.stat().st_size / 1024
        log.info("[PDF] %s (%.0f KB)", pdf_path.name, size_kb)
        return pdf_path

    except Exception as exc:
        log.warning("[PDF] Failed to convert %s: %s", html_path.name, exc)
        return None


async def convert_all_html_to_pdf(directory: Path | str) -> list[Path]:
    """Find every ``*.html`` file under *directory* (recursive) and convert each to PDF.

    Reuses a single Chromium browser instance for all files to avoid the
    overhead of launching a new browser per file.
    """
    directory = Path(directory)
    html_files = sorted(directory.rglob("*.html"))
    if not html_files:
        return []

    pdf_paths: list[Path] = []
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            for html_file in html_files:
                pdf_path = html_file.with_suffix(".pdf")
                try:
                    page = await browser.new_page(viewport={"width": 1280, "height": 900})
                    await page.goto(html_file.as_uri(), wait_until="networkidle")
                    await page.evaluate("""() => {
                        document.querySelectorAll('details:not([open])').forEach(d => d.open = true);
                    }""")
                    await page.wait_for_timeout(300)
                    await page.pdf(
                        path=str(pdf_path),
                        format="A4",
                        landscape=True,
                        print_background=True,
                        margin={"top": "12mm", "right": "10mm", "bottom": "12mm", "left": "10mm"},
                    )
                    await page.close()
                    size_kb = pdf_path.stat().st_size / 1024
                    log.info("[PDF] %s (%.0f KB)", pdf_path.name, size_kb)
                    pdf_paths.append(pdf_path)
                except Exception as exc:
                    log.warning("[PDF] Failed to convert %s: %s", html_file.name, exc)
            await browser.close()
    except Exception as exc:
        log.warning("[PDF] Chromium launch failed, falling back to per-file mode: %s", exc)
        # Fallback: convert individually
        for html_file in html_files:
            result = await html_to_pdf(html_file)
            if result:
                pdf_paths.append(result)

    return pdf_paths
