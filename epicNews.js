import puppeteer from "puppeteer";

// Cache mechanism
let newsCache = null;
let lastFetchTime = null;
const CACHE_DURATION = 15 * 60 * 1000; // 15 minutes in milliseconds

export async function fetchEpicNews() {
  // Check cache first
  if (newsCache && lastFetchTime && (Date.now() - lastFetchTime) < CACHE_DURATION) {
    console.log("Returning cached news data");
    return newsCache;
  }

  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  });

  try {
    console.log("Launching Puppeteer browser...");
    const page = await browser.newPage();

    // Set viewport size
    await page.setViewport({ width: 1920, height: 1080 });

    // Configure request interception to block unnecessary resources
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      const resourceType = request.resourceType();
      if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) {
        request.abort();
      } else {
        request.continue();
      }
    });

    console.log("Navigating to Epic Games news page...");
    await page.goto("https://store.epicgames.com/en-US/news", {
      waitUntil: "networkidle2",
      timeout: 30000
    });

    // Wait for news articles to load
    await page.waitForSelector("section div article", { timeout: 10000 });

    // Scrape news articles
    const newsItems = await page.evaluate(() => {
      const items = [];
      document.querySelectorAll("section div article").forEach((el) => {
        try {
          const title = el.querySelector("h2,h3")?.innerText || "Untitled";
          const url = el.querySelector("a")?.href || "#";
          const img = el.querySelector("img")?.src || "/placeholder-news.jpg";
          const date = el.querySelector("time")?.getAttribute("datetime") || new Date().toISOString();
          const short = el.querySelector("p")?.innerText || "";

          items.push({
            id: crypto.randomUUID(),
            title,
            url,
            image: img,
            date,
            short,
            author: "Epic Games"
          });
        } catch (err) {
          console.error("Error parsing article:", err);
        }
      });
      return items;
    });

    // Update cache
    newsCache = newsItems;
    lastFetchTime = Date.now();
    
    console.log(`Scraped ${newsItems.length} news items`);
    return newsItems;
  } finally {
    await browser.close();
  }
}