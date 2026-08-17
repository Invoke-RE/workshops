#include <iostream>
#include <vector>

class Animal {
public:
	virtual void speak() {
		std::cout << "Generic animal sound." << std::endl;
	}

	virtual ~Animal() {}
};

class Lion : public Animal {
public:
	void speak() override {
		std::cout << "Roar!" << std::endl;
	}

	void hunt() {
		std::cout << "The lion is hunting." << std::endl;
	}
};

class Snake : public Animal {
public:
	void speak() override {
		std::cout << "Hiss!" << std::endl;
	}

	void slither() {
		std::cout << "The snake is slithering." << std::endl;
	}
};

int main() {
	std::vector<Animal*> zoo;

	zoo.push_back(new Lion());
	zoo.push_back(new Snake());

	for (Animal* animal : zoo) {
		animal->speak();
	}

	for (Animal* animal : zoo) {
		Snake* snakePtr = dynamic_cast<Snake*>(animal);

		if (snakePtr) {
			std::cout << "It is a Snake! -> ";
			snakePtr->slither();
		}
		else {
			std::cout << "Not a Snake. Ignoring." << std::endl;
		}
	}

	for (Animal* a : zoo) delete a;

	return 0;
}