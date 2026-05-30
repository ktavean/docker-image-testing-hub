// salvez istoricul scanarilor in localStorage
// backendul e stateless: scanarile finalizate le primesc in eventul de finalizare
// => adaug scanarea in localStorage si o trag de aici in caz ca e nevoie
// localStorage are de obicei ~5 MB, iar o scanare cu tot continutul si loguri
// poate avea cam 50-200 KB; limitez historyul prin MAX_ENTRIES, iar daca scrierea pica pe
// QuotaExceededError, sterg cele mai vechi intrari una cate una pana incape

const KEY     = 'dith_history'
const MAX_ENTRIES = 50

function safeParse(raw) {
  if (!raw) return []
  try {
    const data = JSON.parse(raw)
    return Array.isArray(data) ? data : []
  } catch {
    return []
  }
}

// citesc tot istoricul, sortate descendent dupa data
export function loadHistory() {
  try {
    return safeParse(localStorage.getItem(KEY))
  } catch {
    // localStorage indisponibil (mod privat, etc.) => intorc array gol pentru a evita erori
    return []
  }
}

// inlocuiesc tot istoricul cu entries; intorc true daca a functionat
export function saveHistory(entries) {
  // sortez descendent dupa data si fac slice la MAX_ENTRIES
  const sorted = [...entries].sort((a, b) =>
    (b.created_at || '').localeCompare(a.created_at || '')
  ).slice(0, MAX_ENTRIES)

  try {
    localStorage.setItem(KEY, JSON.stringify(sorted))
    return true
  } catch (e) {
    // prea multe entries => slice la cele mai vechi pana incape cea curenta
    let trimmed = sorted.slice()
    while (trimmed.length > 1) {
      trimmed.pop()  // scot cea mai veche
      try {
        localStorage.setItem(KEY, JSON.stringify(trimmed))
        return true
      } catch { /* daca e vreo eroare, ne intoarcem in loop, nu oprim flowul */ }
    }
    return false
  }
}

// adaug o scanare (sau o inlocuiesc daca id-ul exista deja)
// intorc true daca scrierea a reusit
export function appendScan(scan) {
  if (!scan || !scan.id) return false
  const all = loadHistory()
  // scot orice copie anterioara cu acelasi id (ca sa nu se dubleze din greseala)
  const filtered = all.filter(s => s.id !== scan.id)
  filtered.unshift(scan)  // cea mai noua in fata
  return saveHistory(filtered)
}

// caut o scanare dupa id
export function getScan(id) {
  if (!id) return null
  return loadHistory().find(s => s.id === id) || null
}

// sterg o scanare dupa id
export function deleteScan(id) {
  const all = loadHistory().filter(s => s.id !== id)
  return saveHistory(all)
}

// sterg tot istoricul
export function clearHistory() {
  try {
    localStorage.removeItem(KEY)
    return true
  } catch {
    return false
  }
}

// dimensiunea aproximativa a istoricului, pentru diagnostic
export function historyByteSize() {
  try {
    return (localStorage.getItem(KEY) || '').length
  } catch {
    return 0
  }
}
