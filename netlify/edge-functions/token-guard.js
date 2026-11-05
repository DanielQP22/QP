// Netlify Edge Function: só deixa passar pedidos com o header "X-App-Token" correto.
// O valor esperado vem da variável de ambiente APP_TOKEN (Netlify > Site configuration > Environment variables).
// O token NÃO está escrito aqui de propósito: este repositório pode ser público.

const enc = new TextEncoder();

// Comparação em tempo constante (compara os hashes SHA-256 dos dois valores).
async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

const NO_STORE = { "Cache-Control": "no-store" };

export default async (request, context) => {
  const expected = Netlify.env.get("APP_TOKEN");

  // Sem token configurado, bloqueia tudo (falha segura).
  if (!expected) {
    return new Response("Servidor sem token configurado.", {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8", ...NO_STORE },
    });
  }

  const received = request.headers.get("X-App-Token") ?? "";

  if (!(await safeEqual(received, expected))) {
    return new Response("Acesso negado.", {
      status: 401,
      headers: { "Content-Type": "text/plain; charset=utf-8", ...NO_STORE },
    });
  }

  // Token correto: serve o site normalmente.
  return context.next();
};
