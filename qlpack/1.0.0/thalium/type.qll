/**
 * Provides a hierarchy of type representations used to model program types.
 *
 */

import binary

/**
 * Base class for types.
 */
class Type extends @ens_types {
    /**
     * Gets a printable representation of this type.
     */
    string toString() { result = "Type" }
}

/**
 * Built-in types.
 *
 * Examples:
 * - `void` of 0 byte
 * - `unknown` of 1 byte
 * - `BYTE` of 1 byte
 * - `bool` of 1 byte
 * - `__int8` of 1 byte
 * - `unsigned` of 1 byte
 * - `char` of 1 byte
 * - `unsigned` of 1 byte
 * - `__int16` of 2 bytes
 * - `unsigned` of 2 bytes
 * - `__int32` of 4 bytes
 * - `unsigned` of 4 bytes
 * - `__int64` of 8 bytes
 * - `unsigned` of 8 bytes
 * - `__int128` of 16 bytes
 * - `unsigned` of 16 bytes
 * - `int` of 4 bytes
 * - `unsigned` of 4 bytes
 * - `signed` of 4 bytes
 * - `float` of 4 bytes
 * - `double` of 8 bytes
 * - `long` of 16 bytes
 * - `float` of variable size
 */
final class BasicType extends Type, @basic_type {
    /**
     * Gets a printable representation of this basic type.
     */
    override string toString() { result = this.getName() }
    /**
     * Gets the name of this basic type.
     */
    string getName(){ basic_types(this, result, _, _) }
    /**
     * Gets the kind of this basic type.
     */
    int getKind(){ basic_types(this, _, result, _) }
    /**
     * Gets the size of this basic type, in bytes.
     */
    float getSize(){ basic_types(this, _, _, result) }
}

/**
 * Base class for complex types.
 *
 * Example :
 * - array:     `<T> <name>[N]`
 * - constant:  `const <T> <name>`
 * - enum:      `enum <name>{}`
 * - forward:   `<T> <name>`
 * - function:  `<T> <CC> <name>()`
 * - pointer:   `<T> *<name>`
 * - structure: `struct <name>{}`
 * - typedef:   `typedef <T> <new_T>`
 * - union:     `union <name>{}`
 * - volatile:  `volatile <T> <name>`
 */
class ComplexType extends Type, @complex_types {
    /**
     * Gets a printable representation of this complex type.
     */
    override string toString() { result = "ComplexType"}
}

/**
 * Array type, `<T> <name>[N]`.
 */
final class ArrayType extends ComplexType, @array_type {
    /**
     * Gets a printable representation of this array type, e.g. `int[4]`.
     */
    override string toString() { result = this.getTarget() + "[" + this.getCount() + "]"}

    /**
     * Gets the element type of this array.
     */
    Type getTarget() { array_types(this, result, _, _) }
    /**
     * Gets the number of elements in this array.
     */
    int getCount() { array_types(this, _, result, _) }
    /**
     * Gets the size of this array type, in bytes.
     */
    float getSize() { array_types(this, _, _, result) }
}

/**
 * Constant type, `const <T> <name>`.
 */
final class ConstType extends ComplexType, @const_type {
    /**
     * Gets a printable representation of this const type.
     */
    override string toString() { result = "ConstType"}
    /**
     * Gets the underlying (non-const) type.
     */
    Type getTarget() { const_types(this, result) }
}

/**
 * Enum type, `enum <name>{}`.
 */
final class Enum extends ComplexType, @enum_type {
    /**
     * Gets a printable representation of this enum.
     */
    override string toString() { result = "Enum " + this.getName()}
    /**
     * Gets the name of this enum.
     */
    string getName() { enum_types(this, result, _) }
    /**
     * Gets the enumerator of this enumeration that was declared at the zero-based position index.
     * For example, zero is at index 2 in the following declaration:
     * ```
     * enum ReversedOrder { two = 2, one = 1, zero = 0 };
     * ```
     */
    EnumConstant getEnumConstant(int index){ result = this.getAnEnumConstant() and result.getInt32Value() = index }
    /**
     * Gets an enumerator of this enumeration.
     */
    EnumConstant getAnEnumConstant(){ result.getDeclaringEnum() = this }
    /**
     * Gets the size of this type in bytes.
     */
    int getSize() { enum_types(this, _, result) }
}

/**
 * A C/C++ enumerator, also known as an enumeration constant.
 * For example the enumeration constant `green` in:
 * ```
 * enum {
 *   red,
 *   green,
 *   blue
 * }
 * ```
 */
final class EnumConstant extends ComplexType, @enum_constant {
    /**
     * Gets a printable representation of this enumerator.
     */
    override string toString() { result = "EnumConstant " + this.getName()}

    /**
     * Gets an access to this enumerator.
     */
    EnumConstantAccess getAnAccess(){ result.getTarget() = this }
    /**
     * Gets the enumeration of which this enumerator is a member.
     */
    Enum getDeclaringEnum() { enum_constants(this, _, _, result) }
    /**
     * Gets the name of this enumerator.
     */
    string getName() { enum_constants(this, result, _, _) }
    /**
     * Gets the exact value as a decimal number string - total. See
     * https://github.com/github/codeql/issues/4691.
     */
    string getValue() { enum_constants(this, _, result, _) }

    /**
     * Gets the exact value as an arbitrary-precision `QlBuiltins::BigInt` -
     * total, lossless. Prefer this over `getInt32Value()` for comparisons.
     * Use for comparisons only -- a `BigInt` can't sit in a `select`; use
     * `getValue()`/`getInt32Value()` there.
     */
    QlBuiltins::BigInt getBigIntValue() { result = this.getValue().toBigInt() }

    /**
     * Gets the value as a 32-bit `int`. No result outside `[INT32_MIN,
     * INT32_MAX]` - by design.
     */
    int getInt32Value() {
        exists(QlBuiltins::BigInt v |
            v = this.getBigIntValue() and
            v >= (-2147483648).toBigInt() and
            v <= 2147483647.toBigInt() and
            result = v.toInt()
        )
    }
}

/**
 * Forward type, `<T> <name>`.
 */
final class ForwardType extends ComplexType, @forward_type {
    /**
     * Gets a printable representation of this forward type.
     */
    override string toString() { result = "ForwardType"}
    /**
     * Gets the name of this forward type.
     */
    string getName() { forward_types(this, result) }
}

/**
 * Function pointer type, `<ReturnType> <CC> (*)(<Parameters>)`.
 */
final class FunctionPointerType extends ComplexType, @func_type {
    /**
     * Gets the number of parameters of this function type.
     */
    int getNumberOfParameters() { result = count(int i | exists(this.getParameterType(i))) }
    /**
     * Gets the return type of this function type.
     */
    Type getReturnType() { func_types(this, result, _) }
    /**
     * Gets the type of the parameter at the given zero-based index.
     */
    Type getParameterType(int index) { func_type_args(this, index, result) }
    /**
     * Gets the type of one of this function type's parameters.
     */
    Type getAParameterType() { result = this.getParameterType(_) }
    /**
     * Gets a printable representation of this function type, e.g.
     * `int __cdecl (*)(char *, int)`.
     */
    override string toString() {
        result = this.getReturnType() + " " + this.getCallingConvention() + " (*)(" + this.parameterTypesString(0) + ")"
    }
    /**
     * Gets the calling convention of this function type, e.g. `__cdecl`.
     */
    string getCallingConvention() { func_types(this, _, result) }

    /**
     * Gets a comma-separated string of parameter types starting at index `startIndex`, mirroring
     * `RoutineType.explainParameters()` in the CodeQL C++ standard library.
     */
    private string parameterTypesString(int startIndex) {
        startIndex = 0 and result = "" and not exists(this.getAParameterType())
        or
        (
            if startIndex < max(int j | exists(this.getParameterType(j)))
            then result = this.getParameterType(startIndex).toString() + ", " + this.parameterTypesString(startIndex + 1)
            else result = this.getParameterType(startIndex).toString()
        )
    }
}

/**
 * Pointer type, `<T> *<name>`.
 */
final class PointerType extends ComplexType, @pointer_type {
    /**
     * Gets a printable representation of this pointer type, e.g. `int**`.
     */
    override string toString() { result = repeatStar(this.getDepth()) + this.getTarget()}
    /**
     * Gets the pointed-to type.
     */
    Type getTarget() { pointer_types(this, result, _) }
    /**
     * Gets the pointer indirection depth, e.g. 2 for `int**`.
     */
    int getDepth() { pointer_types(this, _, result) }
}

/**
 * Base class for user-defined types.
 */
class UserType extends ComplexType, @ens_userdefinedtype {
    /**
     * Gets a printable representation of this user-defined type.
     */
    override string toString() { result = "UserType"}
}

/**
 * Structure type, `struct <name>{}`.
 */
class StructureType extends UserType, @struct_type {
    /**
     * Gets a printable representation of this structure type.
     */
    override string toString() { result = "StructureType " + this.getName()}
    /**
     * Gets the name of this structure type.
     */
    string getName() { struct_types(this, result, _) }
    /**
     * Gets the size of this structure type, in bytes.
     */
    float getSize() { struct_types(this, _, result) }
    // StructureField getField(int offset) {
    //     result.getStruct() = this and
    //     result.getOffset() = offset
    // }
    /**
     * Gets a field of this structure.
     */
    Field getAField() { result.getDeclaratingType() = this }
}

/**
 * Typedef type, `typedef <T> <new_T>`.
 */
final class TypedefType extends ComplexType, @typedef_type {
    /**
     * Gets a printable representation of this typedef.
     */
    override string toString() { result = "TypedefType " + this.getTarget() + " " + this.getName() }
    /**
     * Gets the name of this typedef.
     */
    string getName() { typedef_types(this, result, _) }
    /**
     * Gets the underlying type this typedef aliases.
     */
    Type getTarget() { typedef_types(this, _, result) }
}

/**
 * Union Type, `union <name>{}`.
 */
final class UnionType extends UserType, @union_type {
    /**
     * Gets a printable representation of this union type.
     */
    override string toString() { result = "UnionType " + this.getName() }
    /**
     * Gets the name of this union type.
     */
    string getName() { union_types(this, result) }
    /**
     * Same as GetAField() to be equivalent of StructureType
     */
    // bindingset[a] remove `a is not bound to a value`
    // a = a remove unused variable a
    //bindingset[a]
    // Field getField(int a) { result.getUnion() = this and a = a }
    Field getAField() { result.getDeclaratingType() = this }
}

/**
 * Volatile type, `volatile <T> <name>`.
 */
final class VolatileType extends ComplexType, @volatile_type {
    /**
     * Gets a printable representation of this volatile type.
     */
    override string toString() { result = "VolatileType " + this.getTarget() }
    /**
     * Gets the underlying (non-volatile) type.
     */
    Type getTarget() { volatile_types(this, result) }
}

/**
 * Fields, `<T> <name>` in `StructureType` or `UnionType` at a nullable offset.
 */
class Field extends Variable, @field {

    /**
     * Gets a printable representation of this field.
     */
    override string toString() { result = "Field " + this.getType() + " " + this.getName() + " of " + this.getDeclaratingType() }
    /**
     * Gets the name of this field.
     */
    override string getName() { fields(this, result, _, _, _) }
    /**
     * Gets the type of this field.
     */
    override Type getType() { fields(this, _, result, _, _) }
    /**
     * Gets the byte offset of this field within its declaring type.
     */
    int getOffset() { fields(this, _, _, result, _) }

    /**
     * Gets an access to this field.
     */
    override VariableAccess getAnAccess() {
        var_accs(result, this)
    }


    /**
     * Gets the structure or union type declaring this field.
     */
    Type getDeclaratingType(){ fields(this, _, _, _, result) }
}
