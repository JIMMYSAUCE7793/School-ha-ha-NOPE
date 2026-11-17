<?php
$API_KEY = 'YOUR_SERPER_API_KEY_HERE';
$query = trim($_GET['q'] ?? '');

if ($query === '') {
    header('Location: index.html');
    exit;
}

$ch = curl_init('https://google.serper.dev/search');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_HTTPHEADER     => [
        'X-API-KEY: ' . $API_KEY,
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS     => json_encode(['q' => $query]),
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$data = ($httpCode === 200 && $response) ? json_decode($response, true) : null;
$results = $data['organic'] ?? [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title><?php echo htmlspecialchars($query); ?> - Proxy Search</title>
  <style>
    body {
      background: #0f172a;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      max-width: 760px;
      margin: 0 auto;
      padding: 1.5rem 1rem;
    }
    form {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 2rem;
    }
    input {
      flex: 1;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      border: 1px solid #334155;
      background: #1e293b;
      color: #f8fafc;
      font-size: 1rem;
    }
    button {
      padding: 0.75rem 1.25rem;
      border: none;
      border-radius: 8px;
      background: #3b82f6;
      color: #fff;
      font-weight: 600;
      cursor: pointer;
    }
    .result {
      margin-bottom: 1.5rem;
      padding-bottom: 1.25rem;
      border-bottom: 1px solid #1e293b;
    }
    .result a {
      color: #60a5fa;
      font-size: 1.15rem;
      text-decoration: none;
      font-weight: 600;
    }
    .result a:hover { text-decoration: underline; }
    .url { color: #34d399; font-size: 0.85rem; margin: 0.25rem 0; word-break: break-all; }
    .snippet { color: #cbd5e1; font-size: 0.95rem; line-height: 1.45; }
  </style>
</head>
<body>
  <form action="search.php" method="get">
    <input type="text" name="q" value="<?php echo htmlspecialchars($query); ?>" required />
    <button type="submit">Search</button>
  </form>

  <?php if (empty($results)): ?>
    <p>No results found or API quota reached.</p>
  <?php else: ?>
    <?php foreach ($results as $item): ?>
      <div class="result">
        <a href="proxy.php?url=<?php echo urlencode($item['link']); ?>">
          <?php echo htmlspecialchars($item['title']); ?>
        </a>
        <div class="url"><?php echo htmlspecialchars($item['link']); ?></div>
        <div class="snippet"><?php echo htmlspecialchars($item['snippet'] ?? ''); ?></div>
      </div>
    <?php endforeach; ?>
  <?php endif; ?>
</body>
</html>