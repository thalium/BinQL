#include <stdio.h>

struct Animal;

/* VTable */
typedef struct {
    struct Animal* (*speak)(struct Animal *);
    struct Animal* (*rename)(struct Animal *, const char *);
} AnimalVTable;

/* Base struct */
typedef struct Animal {
    const char *name;
    const AnimalVTable *vtable;
} Animal;

/* Dog methods */
Animal* dog_speak(Animal *a) {
    printf("%s says: Woof!\n", a->name);
    return a;
}

Animal* dog_rename(Animal *a, const char *newname) {
    a->name = newname;
    return a;
}

/* VTable instance */
const AnimalVTable dog_vtable = {
    .speak = dog_speak,
    .rename = dog_rename
};

int main() {
    Animal dog = { "Rex", &dog_vtable };

    dog.vtable->rename(&dog, "Buddy")
              ->vtable->speak(&dog);

    return 0;
}
