import { Schema } from 'mongoose';
type Options = {
    rounds?: number;
    fields?: string[];
    field?: string;
};
declare const _default: (schema: Schema, options?: Options) => void;
export default _default;
