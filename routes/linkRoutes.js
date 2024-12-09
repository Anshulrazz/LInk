const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const validator = require('validator'); 
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');

const router = express.Router();

// Add security middleware
router.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
router.use(limiter);

const fetchMetadata = async (url) => {
  try {
    // Sanitize URL
    const sanitizedUrl = validator.trim(xss(url));
    if (!validator.isURL(sanitizedUrl, { require_protocol: true })) {
      throw new Error('Invalid URL format');
    }

    const { data, headers } = await axios.get(sanitizedUrl, {
      timeout: 5000,
      maxRedirects: 5,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; LinkAnalyzer/1.0;)',
      }
    });
    const $ = cheerio.load(data);

    // Check security headers
    const securityHeaders = {
      'Strict-Transport-Security': headers['strict-transport-security'] || 'Not set',
      'Content-Security-Policy': headers['content-security-policy'] || 'Not set',
      'X-Content-Type-Options': headers['x-content-type-options'] || 'Not set',
      'X-Frame-Options': headers['x-frame-options'] || 'Not set',
      'X-XSS-Protection': headers['x-xss-protection'] || 'Not set',
      'Referrer-Policy': headers['referrer-policy'] || 'Not set'
    };

    const isSecure = sanitizedUrl.startsWith('https://');

    // Get all links and images
    const allLinks = [];
    $('a').each((i, elem) => {
      allLinks.push({
        href: $(elem).attr('href'),
        text: $(elem).text().trim()
      });
    });

    const allImages = [];
    $('img').each((i, elem) => {
      allImages.push({
        src: $(elem).attr('src'),
        alt: $(elem).attr('alt'),
        width: $(elem).attr('width'),
        height: $(elem).attr('height')
      });
    });

    return {
      title: xss($('title').text()),
      description: xss($('meta[name="description"]').attr('content') || 'No description available.'),
      keywords: xss($('meta[name="keywords"]').attr('content') || 'No keywords available.'),
      favicon: xss($('link[rel="icon"]').attr('href') || $('link[rel="shortcut icon"]').attr('href')),
      ogImage: xss($('meta[property="og:image"]').attr('content')),
      lastModified: new Date().toISOString(),
      language: xss($('html').attr('lang') || 'Not specified'),
      author: xss($('meta[name="author"]').attr('content') || 'Not specified'),
      siteName: xss($('meta[property="og:site_name"]').attr('content') || 'Not specified'),
      type: xss($('meta[property="og:type"]').attr('content') || 'Not specified'),
      url: xss($('meta[property="og:url"]').attr('content') || sanitizedUrl),
      canonicalUrl: xss($('link[rel="canonical"]').attr('href') || sanitizedUrl),
      robots: xss($('meta[name="robots"]').attr('content') || 'Not specified'),
      themeColor: xss($('meta[name="theme-color"]').attr('content') || 'Not specified'),
      viewport: xss($('meta[name="viewport"]').attr('content') || 'Not specified'),
      generator: xss($('meta[name="generator"]').attr('content') || 'Not specified'),
      copyright: xss($('meta[name="copyright"]').attr('content') || 'Not specified'),
      publisher: xss($('meta[name="publisher"]').attr('content') || 'Not specified'),
      category: xss($('meta[name="category"]').attr('content') || 'Not specified'),
      pageLoadTime: new Date().getTime(),
      contentLength: data.length,
      headingsCount: {
        h1: $('h1').length,
        h2: $('h2').length,
        h3: $('h3').length,
        h4: $('h4').length,
        h5: $('h5').length,
        h6: $('h6').length
      },
      linksCount: $('a').length,
      imagesCount: $('img').length,
      allLinks: allLinks,
      allImages: allImages,
      hasNewsletter: $('form').text().toLowerCase().includes('newsletter'),
      hasSocialLinks: {
        facebook: $('a[href*="facebook.com"]').length > 0,
        twitter: $('a[href*="twitter.com"]').length > 0,
        instagram: $('a[href*="instagram.com"]').length > 0,
        linkedin: $('a[href*="linkedin.com"]').length > 0
      },
      security: {
        isSecure,
        headers: securityHeaders,
        hasSSL: isSecure,
        securityScore: calculateSecurityScore(isSecure, securityHeaders)
      }
    };
  } catch (error) {
    console.error('Error fetching metadata:', error.message);
    return null;
  }
};

// Helper function to calculate security score
const calculateSecurityScore = (isSecure, headers) => {
  let score = 0;
  if (isSecure) score += 30;
  if (headers['Strict-Transport-Security'] !== 'Not set') score += 15;
  if (headers['Content-Security-Policy'] !== 'Not set') score += 15;
  if (headers['X-Content-Type-Options'] !== 'Not set') score += 10;
  if (headers['X-Frame-Options'] !== 'Not set') score += 10;
  if (headers['X-XSS-Protection'] !== 'Not set') score += 10;
  if (headers['Referrer-Policy'] !== 'Not set') score += 10;
  return score;
};

router.post('/analyze', async (req, res) => {
  const { url } = req.body;

  // Sanitize input
  const sanitizedUrl = validator.trim(xss(url));
  if (!validator.isURL(sanitizedUrl, { require_protocol: true })) {
    return res.status(400).json({ message: 'Invalid URL format. Please provide a valid URL with the correct protocol (http/https).' });
  }

  try {
    const metadata = await fetchMetadata(sanitizedUrl);
    if (!metadata) {
      return res.status(400).json({ message: 'Unable to fetch metadata for this URL. It may be invalid or the website is down.' });
    }
    const isValid = metadata.title !== '' && metadata.description !== '';
    res.json({
      success: true,
      message: 'Link analyzed successfully!',
      data: {
        url: sanitizedUrl,
        isValid,
        metadata,
      },
    });
  } catch (err) {
    console.error('Internal server error:', err.message);
    res.status(500).json({ message: 'Internal server error. Please try again later.' });
  }
});

module.exports = router;