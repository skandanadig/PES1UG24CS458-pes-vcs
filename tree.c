// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Forward declarations
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
int index_load(Index *index);

// Recursive helper: build a tree object from a slice of index entries,
// all of which share the given path prefix (at the given depth).
// entries: pointer into the index entries array
// count:   how many entries to consider
// prefix:  the directory prefix already consumed (depth of recursion)
// id_out:  where to write the resulting tree object hash
static int write_tree_level(IndexEntry *entries, int count,
                             const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        if (tree.count >= MAX_TREE_ENTRIES) return -1; // Safety guard
        // Strip the current prefix to work on the remainder of the path
        const char *rel = entries[i].path + strlen(prefix);
        const char *slash = strchr(rel, '/');

        if (slash == NULL) {
            // This is a file directly inside this directory
            TreeEntry *e = &tree.entries[tree.count++];
            e->mode = entries[i].mode;
            strncpy(e->name, rel, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';
            e->hash = entries[i].hash;
            i++;
        } else {
            // This entry belongs to a subdirectory
            // Build the subdir name (everything up to the '/')
            size_t dir_len = slash - rel;
            char dir_name[256];
            if (dir_len >= sizeof(dir_name)) return -1;
            memcpy(dir_name, rel, dir_len);
            dir_name[dir_len] = '\0';

            // Collect all entries that share this same subdirectory prefix
            char new_prefix[512];
            snprintf(new_prefix, sizeof(new_prefix), "%s%s/", prefix, dir_name);
            size_t new_prefix_len = strlen(new_prefix);

            int j = i;
            while (j < count &&
                   strncmp(entries[j].path, new_prefix, new_prefix_len) == 0) {
                j++;
            }

            // Recursively build the subtree for these entries
            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i, new_prefix, &sub_id) != 0)
                return -1;

            // Add the subtree entry to the current tree
            TreeEntry *e = &tree.entries[tree.count++];
            e->mode = MODE_DIR;
            strncpy(e->name, dir_name, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';
            e->hash = sub_id;

            i = j; // Jump past all entries in this subdirectory
        }
    }

    // Serialize the tree and write it to the object store
    void *data;
    size_t data_len;
    if (tree_serialize(&tree, &data, &data_len) != 0) return -1;
    int rc = object_write(OBJ_TREE, data, data_len, id_out);
    free(data);
    return rc;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// NOTE: index_load returns entries in sorted order (index_save sorts them),
// so write_tree_level can rely on all entries for a given subdirectory
// being contiguous in the array.
//
// Returns 0 on success, -1 on error.
int tree_from_index(ObjectID *id_out) {
    Index index;
    if (index_load(&index) != 0) {
        fprintf(stderr, "error: could not load index\n");
        return -1;
    }
    if (index.count == 0) {
        fprintf(stderr, "error: nothing to commit (index is empty)\n");
        return -1;
    }

    return write_tree_level(index.entries, index.count, "", id_out);
}