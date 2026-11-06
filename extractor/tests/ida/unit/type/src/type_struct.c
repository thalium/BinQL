#include <stdio.h>

__attribute__((used, section(".typeinfo")))
const char typeinfo_marker[] =
"typedef void (*SpeakFunc)(struct Animal *);\n"
"struct Animal { const char *name; int age; SpeakFunc speak; };\n"
"enum AnimalType { DOG, CAT };\n"
"typedef struct Animal AnimalTypeDef;\n"
"union Misc { int i; float f; };\n";

struct Animal;

typedef void (*SpeakFunc)(struct Animal *);

struct Animal {
    const char *name;
    int age;
    SpeakFunc speak;
};

void __attribute__((noinline)) dogSpeak(struct Animal *a) {
    printf("%s (%d) says: Woof!\n", a->name, a->age);
}

void __attribute__((noinline)) catSpeak(struct Animal *a) {
    printf("%s (%d) says: Meow!\n", a->name, a->age);
}

void initAnimal(struct Animal *a, SpeakFunc f) {
    a->speak = f;
}

typedef struct Animal AnimalTypeDef;

int main() {

    struct Animal rex = { "Rex", 5, NULL };
    struct Animal whisker = { "Whiskers", 3, NULL };

    initAnimal(&rex, dogSpeak);
    initAnimal(&whisker, catSpeak);

    rex.speak(&rex);
    whisker.speak(&whisker);

    return 0;
}
