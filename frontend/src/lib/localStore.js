// salvez istoricul scanarilor in localStorage-ul navigatorului
// backendul nu tine stare: scanarile gata vin in evenimentul de finalizare
// ca inregistrare completa, eu o adaug aici si afisez istoricul direct de aici
// localStorage are de obicei ~5 MB, iar o scanare cu tot continutul si jurnalul
// poate avea 50-200 KB; limitez la MAX_ENTRIES, iar daca scrierea pica pe
// QuotaExceededError, arunc cele mai vechi intrari una cate una pana incape

const KEY     = 'dhh_history_v1'
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

// citesc tot istoricul, cele mai noi primele
export function loadHistory() {
  try {
    return safeParse(localStorage.getItem(KEY))
  } catch {
    // localStorage indisponibil (mod privat etc.), ma opresc fara zgomot
    return []
  }
}

// inlocuiesc tot istoricul cu entries; intorc true daca a mers
export function saveHistory(entries) {
  // ordonez cu cele mai noi primele si tai la MAX_ENTRIES
  const sorted = [...entries].sort((a, b) =>
    (b.created_at || '').localeCompare(a.created_at || '')
  ).slice(0, MAX_ENTRIES)

  try {
    localStorage.setItem(KEY, JSON.stringify(sorted))
    return true
  } catch (e) {
    // cota depasita, arunc cele mai vechi una cate una si reincerc
    let trimmed = sorted.slice()
    while (trimmed.length > 1) {
      trimmed.pop()  // scot cea mai veche
      try {
        localStorage.setItem(KEY, JSON.stringify(trimmed))
        return true
      } catch { /* continui sa tai */ }
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
