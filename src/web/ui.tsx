// Base UI wrappers adapted from shadcn/ui Base UI registry (MIT). See NOTICE.md.
import * as React from 'react';
import { Button as ButtonPrimitive } from '@base-ui/react/button';
import { Checkbox as CheckboxPrimitive } from '@base-ui/react/checkbox';
import { Collapsible as CollapsiblePrimitive } from '@base-ui/react/collapsible';
import { Radio as RadioPrimitive } from '@base-ui/react/radio';
import { RadioGroup as RadioGroupPrimitive } from '@base-ui/react/radio-group';
import { Switch as SwitchPrimitive } from '@base-ui/react/switch';
import { Tabs } from '@base-ui/react/tabs';

export { Tabs };

const cx = (...values: (string | undefined | false)[]) => values.filter(Boolean).join(' ');

function useControlId(prefix: string): string {
  return `chmcp-${prefix}-${React.useId().replace(/:/g, '')}`;
}

type ButtonProps = ButtonPrimitive.Props & {
  variant?: 'default' | 'primary' | 'danger' | 'ghost' | undefined;
};

export function Button({ variant = 'default', className, type = 'button', ...props }: ButtonProps) {
  return (
    <ButtonPrimitive
      {...props}
      type={type}
      data-variant={variant}
      className={
        typeof className === 'function'
          ? (state) => cx('chmcp-btn', className(state))
          : cx('chmcp-btn', className)
      }
    />
  );
}

type FieldProps = {
  id: string;
  label: React.ReactNode;
  description?: React.ReactNode | undefined;
  error?: React.ReactNode | undefined;
  children: React.ReactElement<{ id?: string | undefined }>;
};

export function Field({ id, label, description, error, children }: FieldProps) {
  const controlId = useControlId(id);
  return (
    <div className="chmcp-field">
      <label className="chmcp-label" htmlFor={controlId}>
        {label}
      </label>
      {React.cloneElement(children, { id: controlId })}
      {description ? <p className="chmcp-muted">{description}</p> : null}
      {error ? (
        <p className="chmcp-field-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function Input({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} autoComplete={props.autoComplete ?? 'off'} className={cx('chmcp-input', className)} />;
}

export function Textarea({ className, ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      autoComplete={props.autoComplete ?? 'off'}
      className={cx('chmcp-input', 'chmcp-textarea', className)}
    />
  );
}

export function Select({ className, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx('chmcp-input', className)} />;
}

type BooleanControlProps = {
  id: string;
  label: React.ReactNode;
  description?: React.ReactNode | undefined;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean | undefined;
};

export function Checkbox({ id, label, description, checked, onChange, disabled }: BooleanControlProps) {
  const controlId = useControlId(id);
  return (
    <div className="chmcp-checkbox">
      <CheckboxPrimitive.Root
        id={controlId}
        checked={checked}
        onCheckedChange={(next) => onChange(next)}
        disabled={disabled}
        className="chmcp-checkbox-box"
        aria-labelledby={`${controlId}-label`}
      >
        <CheckboxPrimitive.Indicator>
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path
              d="m3 8 3.2 3.2L13 4.5"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </CheckboxPrimitive.Indicator>
      </CheckboxPrimitive.Root>
      <div>
        <label id={`${controlId}-label`} htmlFor={controlId} className="chmcp-label">
          {label}
        </label>
        {description ? <p className="chmcp-muted">{description}</p> : null}
      </div>
    </div>
  );
}

export function Toggle({ id, label, description, checked, onChange, disabled }: BooleanControlProps) {
  const controlId = useControlId(id);
  return (
    <div className="chmcp-toggle">
      <div>
        <label id={`${controlId}-label`} htmlFor={controlId} className="chmcp-label">
          {label}
        </label>
        {description ? <p className="chmcp-muted">{description}</p> : null}
      </div>
      <SwitchPrimitive.Root
        id={controlId}
        checked={checked}
        onCheckedChange={(next) => onChange(next)}
        disabled={disabled}
        nativeButton
        render={<button type="button" />}
        className="chmcp-switch"
        aria-labelledby={`${controlId}-label`}
      >
        <SwitchPrimitive.Thumb className="chmcp-switch-thumb" />
      </SwitchPrimitive.Root>
    </div>
  );
}

export type ChoiceOption<V extends string = string> = {
  value: V;
  label: React.ReactNode;
  description?: React.ReactNode | undefined;
};

type ChoiceCardsProps<V extends string> = {
  id: string;
  label: React.ReactNode;
  value: V;
  onChange: (value: V) => void;
  options: ChoiceOption<V>[];
  compact?: boolean | undefined;
  disabled?: boolean | undefined;
};

export function ChoiceCards<V extends string>({
  id,
  label,
  value,
  onChange,
  options,
  compact,
  disabled,
}: ChoiceCardsProps<V>) {
  const controlId = useControlId(id);
  return (
    <div className="chmcp-field">
      <div id={`${controlId}-label`} className="chmcp-label">
        {label}
      </div>
      <RadioGroupPrimitive
        value={value}
        onValueChange={(next) => onChange(next as V)}
        disabled={disabled}
        className={cx('chmcp-choices', compact && 'chmcp-choices--compact')}
        aria-labelledby={`${controlId}-label`}
      >
        {options.map((opt, idx) => {
          const optId = `${controlId}-${idx}`;
          return (
            <label
              key={opt.value}
              htmlFor={optId}
              className="chmcp-choice"
              data-selected={value === opt.value ? '' : undefined}
            >
              <RadioPrimitive.Root id={optId} value={opt.value} className="chmcp-radio">
                <RadioPrimitive.Indicator className="chmcp-radio-dot" />
              </RadioPrimitive.Root>
              <span>
                <span className="chmcp-label">{opt.label}</span>
                {opt.description ? <span className="chmcp-muted" style={{ display: 'block' }}>{opt.description}</span> : null}
              </span>
            </label>
          );
        })}
      </RadioGroupPrimitive>
    </div>
  );
}

type CollapsibleSectionProps = {
  title: React.ReactNode;
  defaultOpen?: boolean | undefined;
  children: React.ReactNode;
};

export function CollapsibleSection({ title, defaultOpen = false, children }: CollapsibleSectionProps) {
  return (
    <CollapsiblePrimitive.Root defaultOpen={defaultOpen} className="chmcp-collapsible">
      <CollapsiblePrimitive.Trigger type="button" className="chmcp-collapsible-trigger">
        <span>{title}</span>
        <span className="chmcp-muted">+/-</span>
      </CollapsiblePrimitive.Trigger>
      <CollapsiblePrimitive.Panel className="chmcp-collapsible-panel">{children}</CollapsiblePrimitive.Panel>
    </CollapsiblePrimitive.Root>
  );
}
