# Security audit: GNOME/glib

Date: 2026-11-22 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 214 issue(s): 19 critical, 195 high.

## Findings

### 1. [HIGH] Use-after-free pattern

**CWE-416** | `girepository/cmph/chd.c` line 40

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 2. [HIGH] Use-after-free pattern

**CWE-416** | `girepository/cmph/chd.c` line 138

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(vals_table);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 3. [HIGH] Use-after-free pattern

**CWE-416** | `girepository/cmph/chd.c` line 227

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 4. [HIGH] Use-after-free pattern

**CWE-416** | `girepository/cmph/chd.c` line 228

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(mphf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 5. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 21

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
chd = (chd_config_data_t *)malloc(sizeof(chd_config_data_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 6. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 108

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
packed_chd_phf = calloc((size_t)packed_chd_phf_size,(size_t)1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 7. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 126

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
vals_table = (cmph_uint32 *)calloc(nvals, sizeof(cmph_uint32));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 8. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 141

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
packed_cr = (cmph_uint8 *) calloc(packed_cr_size, sizeof(cmph_uint8));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 9. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 145

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
mphf = (cmph_t *)malloc(sizeof(cmph_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 10. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 147

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
chdf = (chd_data_t *)malloc(sizeof(chd_data_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 11. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 179

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
chd_data_t *chd = (chd_data_t *)malloc(sizeof(chd_data_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 12. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 186

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
chd->packed_chd_phf = (cmph_uint8 *) calloc((size_t)chd->packed_chd_phf_size,(size_t)1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 13. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/chd.c` line 191

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
chd->packed_cr = (cmph_uint8 *) calloc((size_t)chd->packed_cr_size, (size_t)1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 14. [HIGH] Integer overflow in size calculation

**CWE-190** | `gio/gfileattribute.c` line 198

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
escaped_val = g_malloc (len + num_invalid * 3 + 1);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 15. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gfileattribute.c` line 47

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (attr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 16. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gfileattribute.c` line 798

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (list);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 17. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 96

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
attr->u.string = g_strdup (attr->u.string);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 18. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 190

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
return g_strdup (str);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 19. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 198

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
escaped_val = g_malloc (len + num_invalid * 3 + 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 20. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 241

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
str = g_strdup (attr->u.string);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 21. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 278

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
str = g_strdup ("<unset>");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 22. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 282

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
str = g_strdup ("<invalid>");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 23. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 474

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
value->u.string = g_strdup (value_p);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 24. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 538

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
attr->u.string = g_strdup (string);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 25. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 557

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
attr->u.string = g_strdup (string);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 26. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 747

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new->public.infos[i].name = g_strdup (list->infos[i].name);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 27. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gfileattribute.c` line 885

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
info.name = g_strdup (name);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 28. [HIGH] Use-after-free pattern

**CWE-416** | `glib/tests/642026.c` line 90

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_cond_free (cond);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 29. [HIGH] Use-after-free pattern

**CWE-416** | `glib/tests/642026.c` line 92

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_mutex_free (mutex);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 30. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gdatetime.c` line 2928

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
g_string_append_printf (outstr, ":%02d", minutes);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 31. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gdatetime.c` line 2931

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
g_string_append_printf (outstr, ":%02d", seconds);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 32. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 2983

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (digit);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 33. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3064

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 34. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3080

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 35. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3082

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (static_era_description_locale);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 36. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3159

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (alt_digits_locale);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 37. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3214

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 38. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3217

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (ampm_dup);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 39. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3248

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (utf8_format);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 40. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3276

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (utf8);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 41. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3280

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (utf8);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 42. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3283

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 43. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3877

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (main_date);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 44. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gdatetime.c` line 3891

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (time_zone);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 45. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/gdatetime.c` line 3083

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
static_era_description_locale = g_strdup (current_lc_time);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 46. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/gdatetime.c` line 3160

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
alt_digits_locale = g_strdup (current_ctype_locale);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 47. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/tests/gpoll.c` line 339

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
g_printerr ("1-socket + msg poll time:\n%4lldns - %4lldns, average %4lldns\n", times_min, times_max, times_avg);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 48. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/tests/gpoll.c` line 494

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
g_printerr ("half-socket + msg poll time:\n%4lldns - %4lldns, average %4lldns\n", times_min, times_max, times_avg);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 49. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/tests/gpoll.c` line 602

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
g_printerr ("variable socket number + msg poll time: \n%4lldns - %4lldns, average %4lldns\n", times_min, times_max, times_avg);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 50. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gdbusmenumodel.c` line 292

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 51. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gdbusmenumodel.c` line 517

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 52. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gdbusmenumodel.c` line 221

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
id->bus_name = g_strdup (cid->bus_name);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 53. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gdbusmenumodel.c` line 222

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
id->object_path = g_strdup (cid->object_path);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 54. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gdbusmenumodel.c` line 419

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (item->links, g_strdup (key + 1), g_variant_ref (value));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 55. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gdbusmenumodel.c` line 421

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (item->attributes, g_strdup (key), g_variant_ref (value));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 56. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/gdbusmenumodel.c` line 797

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (*table, g_strdup (key), link);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 57. [HIGH] Integer overflow in size calculation

**CWE-190** | `girepository/cmph/select.c` line 231

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
*buf = (char *)calloc(*buflen, sizeof(char));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 58. [HIGH] Use-after-free pattern

**CWE-416** | `girepository/cmph/select.c` line 299

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 59. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/select.c` line 114

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sel->bits_vec = (cmph_uint32 *)calloc(vec_size, sizeof(cmph_uint32));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 60. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/select.c` line 120

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sel->select_table = (cmph_uint32 *)calloc(sel_table_size, sizeof(cmph_uint32));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 61. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/select.c` line 231

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
*buf = (char *)calloc(*buflen, sizeof(char));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 62. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/select.c` line 270

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sel->bits_vec = (cmph_uint32 *)calloc(vec_size/sizeof(cmph_uint32), sizeof(cmph_uint32));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 63. [HIGH] Missing NULL check after allocation

**CWE-476** | `girepository/cmph/select.c` line 276

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sel->select_table = (cmph_uint32 *)calloc(sel_table_size/sizeof(cmph_uint32), sizeof(cmph_uint32));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 64. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-sessionbus.c` line 41

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (relative);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 65. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-sessionbus.c` line 44

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (servicesdir);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 66. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `glib/tests/rec-mutex.c` line 278

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf (name, "/thread/rec-mutex/perf/contended%d/depth%d", i, j);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 67. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `glib/tests/rec-mutex.c` line 280

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf (name, "/thread/rec-mutex/perf/uncontended/depth%d", j);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 68. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/tests/rec-mutex.c` line 278

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
sprintf (name, "/thread/rec-mutex/perf/contended%d/depth%d", i, j);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 69. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/tests/rec-mutex.c` line 280

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
sprintf (name, "/thread/rec-mutex/perf/uncontended/depth%d", j);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 70. [HIGH] Use-after-free pattern

**CWE-416** | `glib/tests/rec-mutex.c` line 146

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_rand_free (rand);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 71. [HIGH] Integer overflow in size calculation

**CWE-190** | `glib/grcbox.c` line 99

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
allocated = g_malloc (real_size + sizeof (gpointer));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 72. [HIGH] Use-after-free pattern

**CWE-416** | `glib/grcbox.c` line 353

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (real_mem);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 73. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/grcbox.c` line 99

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
allocated = g_malloc (real_size + sizeof (gpointer));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 74. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/grcbox.c` line 112

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
allocated = g_malloc (real_size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 75. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/fileattributematcher.c` line 23

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (s);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 76. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/fileattributematcher.c` line 64

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (s);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 77. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/fileattributematcher.c` line 145

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (s);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 78. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 239

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free ( response);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 79. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 252

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (reply1);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 80. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 253

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (reply2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 81. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 311

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (ret_string);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 82. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 312

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (ret_objpath);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 83. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 313

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (ret_signature);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 84. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 435

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 85. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 445

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 86. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 455

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 87. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 459

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter1);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 88. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 460

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 89. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 461

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter3);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 90. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 565

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp1);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 91. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 566

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 92. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 580

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp1);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 93. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 581

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 94. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 595

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp1);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 95. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 596

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 96. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 626

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 97. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 627

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter1);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 98. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 635

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (tmp);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 99. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 637

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_variant_iter_free (iter2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 100. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 644

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (desc_ret);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 101. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 730

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (str_ret);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 102. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-testserver.c` line 731

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (path_ret);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 103. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 703

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_replace (properties, g_strdup ("PropertyThatWillBeInvalidated"), g_variant_ref_sink (g_variant_new_string (value)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 104. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 852

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("y"), g_variant_ref_sink (g_variant_new_byte (1)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 105. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 853

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("b"), g_variant_ref_sink (g_variant_new_boolean (TRUE)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 106. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 854

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("n"), g_variant_ref_sink (g_variant_new_int16 (2)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 107. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 855

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("q"), g_variant_ref_sink (g_variant_new_uint16 (3)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 108. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 856

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("i"), g_variant_ref_sink (g_variant_new_int32 (4)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 109. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 857

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("u"), g_variant_ref_sink (g_variant_new_uint32 (5)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 110. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 858

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("x"), g_variant_ref_sink (g_variant_new_int64 (6)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 111. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 859

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("t"), g_variant_ref_sink (g_variant_new_uint64 (7)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 112. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 860

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("d"), g_variant_ref_sink (g_variant_new_double (7.5)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 113. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 861

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("s"), g_variant_ref_sink (g_variant_new_string ("a string")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 114. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 862

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("o"), g_variant_ref_sink (g_variant_new_object_path ("/some/path")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 115. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 863

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("ay"), g_variant_ref_sink (g_variant_new_parsed ("[@y 1, @y 11]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 116. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 864

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("ab"), g_variant_ref_sink (g_variant_new_parsed ("[true, false]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 117. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 865

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("an"), g_variant_ref_sink (g_variant_new_parsed ("[@n 2, @n 12]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 118. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 866

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("aq"), g_variant_ref_sink (g_variant_new_parsed ("[@q 3, @q 13]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 119. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 867

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("ai"), g_variant_ref_sink (g_variant_new_parsed ("[@i 4, @i 14]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 120. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 868

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("au"), g_variant_ref_sink (g_variant_new_parsed ("[@u 5, @u 15]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 121. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 869

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("ax"), g_variant_ref_sink (g_variant_new_parsed ("[@x 6, @x 16]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 122. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 870

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("at"), g_variant_ref_sink (g_variant_new_parsed ("[@t 7, @t 17]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 123. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 871

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("ad"), g_variant_ref_sink (g_variant_new_parsed ("[7.5, 17.5]")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 124. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 872

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("as"), g_variant_ref_sink (g_variant_new_parsed ("['a string', 'another string']")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 125. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 873

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("ao"), g_variant_ref_sink (g_variant_new_parsed ("[@o '/some/path', @o '/another/path']")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 126. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 874

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("foo"), g_variant_ref_sink (g_variant_new_string ("a frobbed string")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 127. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-testserver.c` line 875

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
g_hash_table_insert (properties, g_strdup ("PropertyThatWillBeInvalidated"), g_variant_ref_sink (g_variant_new_string ("InitialValue")));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 128. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gsettings-mapping.c` line 440

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (type_string);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 129. [HIGH] Use-after-free pattern

**CWE-416** | `glib/tests/thread-pool.c` line 351

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
test_stop_unused_during_free (void)
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 130. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gsimpleasyncresult.c` line 878

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 131. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gnulib/printf.h` line 28

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
int _g_gnulib_sprintf   (char       *string,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 132. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gnulib/printf.h` line 31

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
int _g_gnulib_snprintf  (char       *string,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 133. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gnulib/printf.h` line 40

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
int _g_gnulib_vsprintf  (char       *string,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 134. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gnulib/printf.h` line 43

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
int _g_gnulib_vsnprintf (char       *string,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 135. [HIGH] Missing NULL check after allocation

**CWE-476** | `gobject/tests/notify-init.c` line 88

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
obj->baz = g_strdup (baz);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 136. [HIGH] Missing NULL check after allocation

**CWE-476** | `gobject/tests/notify-init.c` line 102

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
obj->quux = g_strdup (quux);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 137. [HIGH] Missing NULL check after allocation

**CWE-476** | `gobject/tests/notify-init.c` line 244

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
self->baz = g_strdup ("Hello");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 138. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `glib/gmarkup.c` line 686

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
strcpy (to, buf);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 139. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gmarkup.c` line 2401

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
g_string_append_printf (str, "&#x%x;", c);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 140. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gmarkup.c` line 2412

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
g_string_append_printf (str, "&#x%x;", u);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 141. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gmarkup.c` line 2686

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
output1 = g_strdup_vprintf (format1->str, args);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 142. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/gmarkup.c` line 2694

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
output2 = g_strdup_vprintf (format2->str, args2);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 143. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 277

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_markup_parse_context_free (context);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 144. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 323

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (context);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 145. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 397

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (s);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 146. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 398

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (s_valid);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 147. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 544

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (temp);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 148. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 585

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (s);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 149. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 2730

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (escaped);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 150. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 2740

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (output1);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 151. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gmarkup.c` line 2741

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (output2);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 152. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/gmarkup.c` line 2998

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
*str_ptr = g_strdup (value);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 153. [CRITICAL] Format string vulnerability

**CWE-134** | `glib/guri.c` line 1721

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
g_string_append_printf (str, ":%d", port);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 154. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 531

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (addr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 155. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 532

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (decoded_zone_id);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 156. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 537

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (addr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 157. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 538

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (decoded_zone_id);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 158. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 571

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (addr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 159. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 593

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (decoded);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 160. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 605

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (decoded);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 161. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 620

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (host);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 162. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 621

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (decoded);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 163. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1020

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (normalized_scheme);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 164. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1021

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (cleaned_uri_string);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 165. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1040

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (normalized_scheme);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 166. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1041

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (cleaned_uri_string);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 167. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1230

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (my_scheme);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 168. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1231

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (my_host);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 169. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1241

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (my_scheme);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 170. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1242

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (my_host);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 171. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1290

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (my_scheme);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 172. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 1731

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (normalized_scheme);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 173. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 2268

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (decoded_attr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 174. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 2277

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (decoded_attr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 175. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 2278

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (decoded_value);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 176. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 2655

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (unescaped);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 177. [HIGH] Use-after-free pattern

**CWE-416** | `glib/guri.c` line 2902

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (lower_scheme);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 178. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1013

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
*path = g_strdup ("/");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 179. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1473

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->scheme = g_strdup (base_uri->scheme);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 180. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1481

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->path = g_strdup (base_uri->path);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 181. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1483

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->query = g_strdup (base_uri->query);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 182. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1511

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->userinfo = g_strdup (base_uri->userinfo);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 183. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1512

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->user = g_strdup (base_uri->user);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 184. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1513

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->password = g_strdup (base_uri->password);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 185. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1514

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->auth_params = g_strdup (base_uri->auth_params);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 186. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1515

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->host = g_strdup (base_uri->host);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 187. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1527

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->path = g_strdup ("/");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 188. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1899

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->userinfo = g_strdup (userinfo);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 189. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1900

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->host = g_strdup (host);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 190. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1902

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->path = g_strdup (path);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 191. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1903

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->query = g_strdup (query);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 192. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1904

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->fragment = g_strdup (fragment);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 193. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1959

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->user = g_strdup (user);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 194. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1960

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->password = g_strdup (password);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 195. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1961

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->auth_params = g_strdup (auth_params);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 196. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1962

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->host = g_strdup (host);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 197. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1964

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->path = g_strdup (path);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 198. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1965

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->query = g_strdup (query);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 199. [HIGH] Missing NULL check after allocation

**CWE-476** | `glib/guri.c` line 1966

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri->fragment = g_strdup (fragment);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 200. [HIGH] Use-after-free pattern

**CWE-416** | `glib/gtimer.c` line 108

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (timer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 201. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-daemon.c` line 38

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_option_context_free (context);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 202. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gmemorymonitorwin32.c` line 103

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (emsg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 203. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gmemorymonitorwin32.c` line 119

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (emsg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 204. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gmemorymonitorwin32.c` line 133

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (emsg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 205. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gmemorymonitorwin32.c` line 166

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (emsg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 206. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gmemorymonitorwin32.c` line 181

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (weak_ref);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 207. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gmemorymonitorwin32.c` line 218

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (weak_ref);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 208. [HIGH] Use-after-free pattern

**CWE-416** | `gio/gfileenumerator.c` line 845

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_error_free (error); /* Never propagate cancel errors to other call */
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 209. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-connection-loss.c` line 127

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (path);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 210. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-peer-object-manager.c` line 245

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (guid);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 211. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-peer-object-manager.c` line 372

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (number2_path);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 212. [HIGH] Use-after-free pattern

**CWE-416** | `gio/tests/gdbus-peer-object-manager.c` line 373

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
g_free (number1_path);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 213. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-peer-object-manager.c` line 306

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
number1_path = g_strdup ("/number_1");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 214. [HIGH] Missing NULL check after allocation

**CWE-476** | `gio/tests/gdbus-peer-object-manager.c` line 307

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
number2_path = g_strdup ("/number_2");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---
