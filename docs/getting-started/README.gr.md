# Οδηγός για το Ξεκίνημα (Getting Started)

Για την πρώτη σας εγκατάσταση και για μια γρήγορη γνωριμία με το σύστημα.

## Πώς να Ξεκινήσετε

1. **Γενική παρουσίαση και γρήγορη εκκίνηση:** [../../README.md](../../README.md)
2. **Εγκατάσταση με ένα κλικ και διπλή λειτουργία:** [../one-click-bootstrap.md](../one-click-bootstrap.md)
3. **Βρείτε εντολές ανάλογα με την εργασία που θέλετε να κάνετε:** [../commands-reference.md](../commands-reference.md)

---

## Πώς θα προχωρήσετε

| Τι θέλετε να κάνετε | Εντολή |
| :--- | :--- |
| Έχω κλειδί API και θέλω την πιο γρήγορη εγκατάσταση | `zeroclaw onboard --api-key sk-... --provider openrouter` |
| Θέλω βοήθεια βήμα-βήμα με ερωτήσεις | `zeroclaw onboard --interactive` |
| Οι ρυθμίσεις υπάρχουν, θέλω μόνο να φτιάξω τα κανάλια | `zeroclaw onboard --channels-only` |
| Οι ρυθμίσεις υπάρχουν, αλλά θέλω να τις αντικαταστήσω όλες | `zeroclaw onboard --force` |
| Χρήση με κωδικούς συνδρομής | Δείτε το [Subscription Auth](../../README.md#subscription-auth-openai-codex--claude-code) |

---

## Ρύθμιση και Έλεγχος

* **Γρήγορη ρύθμιση:** `zeroclaw onboard --api-key "sk-..." --provider openrouter`
* **Ρύθμιση με ερωτήσεις:** `zeroclaw onboard --interactive`
* **Προστασία ρυθμίσεων:** Αν ξανατρέξετε τη διαδικασία, το σύστημα θα σας ζητήσει επιβεβαίωση (εκτός αν χρησιμοποιήσετε την εντολή `--force`).
* **Μοντέλα Ollama cloud (`:cloud`):** Χρειάζονται μια διεύθυνση `api_url` και ένα κλειδί API (π.χ. `api_url = "https://ollama.com"`).
* **Έλεγχος καλής λειτουργίας:** Χρησιμοποιήστε τις εντολές `zeroclaw status` και `zeroclaw doctor` για να βεβαιωθείτε ότι όλα δουλεύουν σωστά.

## Επόμενα Βήματα

* **Λειτουργίες την ώρα που τρέχει το πρόγραμμα:** [../operations/README.md](../operations/
