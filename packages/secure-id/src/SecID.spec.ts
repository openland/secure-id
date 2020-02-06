import { SecIDFactory } from './SecID';

describe('SecID Module', () => {
    it('Factory should work', () => {
        let factory = new SecIDFactory('Shared Secret');
        factory.createId('First Type');
        factory.createId('Second Type');
    });
    it('Should serialize correctly', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let id = factory.createId('IdType');
        let serialized = id.serialize(123);
        let parsed = id.parse(serialized);
        expect(parsed).toEqual(123);
        expect(serialized).toEqual('7e1f9518ed46bbb81e74366583b6d0');
        let stringId = factory.createStringId('IdType2');
        serialized = stringId.serialize('test');
        let parsed2 = stringId.parse(serialized);
        expect(parsed2).toEqual('test');
        expect(serialized).toEqual('7d225718e932a56b5ecc8283b6d7bce593');
        expect(stringId.parse(stringId.serialize('')));
    });
    it('Should serialize non-ASCII text correctly', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let id = factory.createStringId('IdType');
        let serialized = id.serialize('тест🤔');
        let parsed = id.parse(serialized);
        expect(parsed).toEqual('тест🤔');
        expect(serialized).toEqual('7d1f9518e19742c89fc1f3f64aeee4599a14ba66c30d03bb48');
    });
    it('Should handle crash on collisions', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        factory.createId('idtype');
        expect(() => factory.createId('idtype')).toThrow();
    });
    it('should not depend on capitalization of type', () => {
        let factory1 = new SecIDFactory('Shared Secret', 'hex');
        let factory2 = new SecIDFactory('Shared Secret', 'hex');
        let type1 = factory1.createId('type');
        let type2 = factory2.createId('TYPE');
        expect(type1.serialize(123)).toBe(type2.serialize(123));
    });
    it('Serialization should be consistent', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let id = factory.createId('idtype');
        let main = id.serialize(123);
        for (let i = 0; i < 10; i++) {
            expect(id.serialize(123)).toEqual(main);
        }
    });
    it('should serialize differently for different types', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let type1 = factory.createId('type1');
        let type2 = factory.createId('type2');
        expect(type1.serialize(123)).not.toBe(type2.serialize(123));
    });
    it('should crash on negative numbers', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let type1 = factory.createId('type1');
        expect(() => type1.serialize(-1)).toThrow('Ids can\'t be negative!');
    });

    it('should crash on float numbers', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let type1 = factory.createId('type1');
        expect(() => type1.serialize(0.1)).toThrow('Ids can\'t be float numbers!');
    });
    it('should crash on incorrect input', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let type1 = factory.createId('type1');
        expect(() => type1.parse('somestring')).toThrow('Invalid id');
        expect(() => type1.parse('7e1f9518ed46bbb81e74366583b6d0')).toThrow('Invalid id');
    });

    it('should resolve type', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let type1 = factory.createId('type1');
        factory.createId('type2');
        factory.createId('type3');
        factory.createId('type4');
        let res = factory.resolve(type1.serialize(123));
        expect(res.id).toEqual(123);
        expect(res.type).toEqual(type1);

        let type7 = factory.createStringId('type7');
        res = factory.resolve(type7.serialize('123'));
        expect(res.id).toEqual('123');
        expect(res.type).toEqual(type7);
    });

    it('should handle large numbers', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let type1 = factory.createId('type1');
        expect(type1.parse(type1.serialize(2147483647))).toEqual(2147483647);
    });
    it('should crash for too large numbers', () => {
        let factory = new SecIDFactory('Shared Secret', 'hex');
        let type1 = factory.createId('type1');
        expect(() => type1.serialize(2147483648)).toThrow();
    });
});
