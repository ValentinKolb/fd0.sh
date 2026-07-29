import { password, type PasswordStrength } from "@k2b/stdlib";

export type GeneratorMode = "random" | "memorable" | "pin";

export type GeneratorSettings = {
  mode: GeneratorMode;
  length: number;
  uppercase: boolean;
  numbers: boolean;
  symbols: boolean;
  words: number;
  separator: string;
  capitalize: boolean;
  addNumber: boolean;
  addSymbol: boolean;
  pinLength: number;
};

export const defaultGeneratorSettings: GeneratorSettings = {
  mode: "random",
  length: 24,
  uppercase: true,
  numbers: true,
  symbols: true,
  words: 6,
  separator: "-",
  capitalize: false,
  addNumber: true,
  addSymbol: false,
  pinLength: 6,
};

export function generatePassword(settings: GeneratorSettings): string {
  switch (settings.mode) {
    case "memorable":
      return password.memorable({
        words: settings.words,
        separator: settings.separator,
        capitalize: settings.capitalize,
        fullWords: true,
        addNumber: settings.addNumber,
        addSymbol: settings.addSymbol,
      });
    case "pin":
      return password.pin({ length: settings.pinLength });
    default:
      return password.random({
        length: settings.length,
        uppercase: settings.uppercase,
        numbers: settings.numbers,
        symbols: settings.symbols,
      });
  }
}

export function passwordStrength(value: string): PasswordStrength {
  return password.strength(value);
}
